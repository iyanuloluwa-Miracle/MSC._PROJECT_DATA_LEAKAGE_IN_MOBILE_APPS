"""Static APK Parser leveraging AndroGuard for package structure and manifest extraction."""

from __future__ import annotations

import hashlib
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.exceptions import (
    APKParsingError,
    InvalidAPKError,
)
from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.models import (
    ApplicationMetadata,
    ManifestData,
    ParsedAPKData,
)
from data_leak_detector.core.path_safety import is_safe_zip_path


logger = logging.getLogger(__name__)


class APKParser:
    """Performs static-only inspection and metadata extraction on Android APK files.
    
    Guarantees:
    - Never executes or installs the APK.
    - Validates file existence, file type, and ZIP archive integrity before parsing.
    - Enforces configurable limits on archive size, entry counts, and decompression ratios.
    - Neutralizes Zip Slip / Path Traversal archive entries.
    - Gracefully handles malformed or corrupted packages.
    - Sanitizes logging to prevent exposing raw secrets.
    """

    CHUNK_SIZE = 65536  # 64 KB read buffer for hashing

    def __init__(self, apk_path: Path | str, config: AppConfig | None = None) -> None:
        self.apk_path = Path(apk_path).resolve()
        self.config = config or AppConfig()

    def validate_file(self) -> None:
        """Validate that the target path exists, is a regular file, and has valid ZIP/APK structure."""
        if not self.apk_path.exists():
            raise InvalidAPKError(f"APK file does not exist: {self.apk_path}")
        if not self.apk_path.is_file():
            raise InvalidAPKError(f"APK path is not a regular file: {self.apk_path}")

        file_size = self.apk_path.stat().st_size
        if file_size == 0:
            raise InvalidAPKError(f"APK file is empty (0 bytes): {self.apk_path.name}")

        if file_size > self.config.max_apk_size_bytes:
            raise InvalidAPKError(
                f"APK file size ({file_size} bytes) exceeds configured maximum limit "
                f"({self.config.max_apk_size_bytes} bytes): {self.apk_path.name}"
            )

        # Validate ZIP archive structure
        if not zipfile.is_zipfile(self.apk_path):
            raise InvalidAPKError(f"Target file is not a valid ZIP/APK archive: {self.apk_path.name}")

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                # Check for zip corruption
                bad_file = zf.testzip()
                if bad_file is not None:
                    raise InvalidAPKError(
                        f"APK archive contains corrupted file entry: {bad_file}"
                    )

                infolist = zf.infolist()
                if len(infolist) > self.config.max_extracted_file_count:
                    raise InvalidAPKError(
                        f"APK archive contains {len(infolist)} entries, exceeding maximum allowed count "
                        f"({self.config.max_extracted_file_count})."
                    )

                total_uncompressed = 0
                has_manifest = False
                has_dex = False

                for info in infolist:
                    entry_name = info.filename
                    if not is_safe_zip_path(entry_name):
                        raise InvalidAPKError(
                            f"Insecure ZIP archive entry detected (Path Traversal / Zip Slip attempt): {entry_name}"
                        )

                    total_uncompressed += info.file_size
                    # Check for decompression bomb / extreme compression ratio
                    if (
                        info.compress_size > 0
                        and info.file_size > 10 * 1024 * 1024
                        and (info.file_size / info.compress_size > 200)
                    ):
                        raise InvalidAPKError(
                            f"Suspiciously high compression ratio detected (potential Zip Bomb): {entry_name}"
                        )

                    if entry_name == "AndroidManifest.xml":
                        has_manifest = True
                    elif entry_name.endswith(".dex"):
                        has_dex = True

                if total_uncompressed > self.config.max_extracted_size_bytes:
                    raise InvalidAPKError(
                        f"Total uncompressed archive size ({total_uncompressed} bytes) exceeds limit "
                        f"({self.config.max_extracted_size_bytes} bytes)."
                    )

                if not (has_manifest or has_dex):
                    raise InvalidAPKError(
                        f"Archive '{self.apk_path.name}' lacks Android package indicators "
                        "(AndroidManifest.xml or .dex files)."
                    )
        except zipfile.BadZipFile as e:
            raise InvalidAPKError(f"Corrupted or invalid ZIP/APK archive: {e}") from e
        except InvalidAPKError:
            raise
        except Exception as e:
            raise InvalidAPKError(f"Failed to inspect APK archive: {e}") from e

    def calculate_sha256(self) -> str:
        """Calculate SHA-256 hash securely by streaming in chunks."""
        hasher = hashlib.sha256()
        try:
            with open(self.apk_path, "rb") as f:
                while chunk := f.read(self.CHUNK_SIZE):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            raise APKParsingError(f"Failed to calculate SHA-256 hash: {e}") from e

    def parse(self) -> ParsedAPKData:
        """Statically parse APK using AndroGuard and return a structured ParsedAPKData object."""
        self.validate_file()
        file_size = self.apk_path.stat().st_size
        sha256 = self.calculate_sha256()

        androguard_apk = self._load_androguard_apk()

        try:
            package_name = androguard_apk.get_package() or "unknown.package"
            app_name = androguard_apk.get_app_name()
            version_name = androguard_apk.get_androidversion_name()
            version_code = androguard_apk.get_androidversion_code()
            min_sdk = androguard_apk.get_min_sdk_version()
            target_sdk = androguard_apk.get_target_sdk_version()

            permissions = list(androguard_apk.get_permissions() or [])
            declared_permissions = list(androguard_apk.get_declared_permissions() or [])
            activities = list(androguard_apk.get_activities() or [])
            services = list(androguard_apk.get_services() or [])
            receivers = list(androguard_apk.get_receivers() or [])
            providers = list(androguard_apk.get_providers() or [])
            features = list(androguard_apk.get_features() or [])
            libraries = list(androguard_apk.get_libraries() or [])

            # Extract manifest flags and raw XML
            manifest_info = self._extract_manifest_info(androguard_apk, package_name, app_name)

            metadata = ApplicationMetadata(
                filename=self.apk_path.name,
                sha256=sha256,
                file_size=file_size,
                package_name=package_name,
                file_path=self.apk_path,
                app_name=app_name,
                version_name=version_name,
                version_code=version_code,
                min_sdk=min_sdk,
                target_sdk=target_sdk,
                analyzed_at=datetime.now(timezone.utc),
            )

            logger.info(
                SensitiveDataFilter.redact(
                    f"Successfully parsed APK '{metadata.filename}' (package: {metadata.package_name})"
                )
            )

            return ParsedAPKData(
                metadata=metadata,
                permissions=permissions,
                declared_permissions=declared_permissions,
                activities=activities,
                services=services,
                receivers=receivers,
                providers=providers,
                features=features,
                libraries=libraries,
                manifest_info=manifest_info,
                is_valid_apk=True,
            )

        except Exception as e:
            sanitized_err = SensitiveDataFilter.redact(str(e))
            logger.error(f"Error parsing APK structure: {sanitized_err}")
            raise APKParsingError(f"Failed to extract APK information: {sanitized_err}") from e

    def extract_metadata(self) -> ApplicationMetadata:
        """Quickly extract baseline ApplicationMetadata."""
        return self.parse().metadata

    def _load_androguard_apk(self) -> Any:
        """Import AndroGuard and initialize the APK parser object."""
        try:
            try:
                from androguard.core.apk import APK
            except ImportError:
                from androguard.core.bytecodes.apk import APK  # type: ignore
        except ImportError as e:
            raise APKParsingError(
                "AndroGuard is not installed. Please install 'androguard' to enable static analysis."
            ) from e

        try:
            apk_obj = APK(str(self.apk_path))
            if not apk_obj.is_valid_APK():
                raise APKParsingError("AndroGuard determined the APK file is invalid or corrupted.")
            return apk_obj
        except APKParsingError:
            raise
        except Exception as e:
            sanitized_err = SensitiveDataFilter.redact(str(e))
            raise APKParsingError(f"AndroGuard failed to parse APK: {sanitized_err}") from e

    def _extract_manifest_info(
        self, apk_obj: Any, package_name: str, app_name: str | None
    ) -> ManifestData:
        """Extract security flags, network security configuration, and component elements."""
        allow_backup = self._parse_bool_attribute(apk_obj, "application", "allowBackup")
        debuggable = self._parse_bool_attribute(apk_obj, "application", "debuggable")
        uses_cleartext = self._parse_bool_attribute(apk_obj, "application", "usesCleartextTraffic")
        net_sec_config = None
        try:
            val = apk_obj.get_attribute_value("application", "networkSecurityConfig")
            if val:
                net_sec_config = str(val)
        except Exception:
            pass

        raw_xml: str | None = None
        components: list[Any] = []
        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
            if manifest_xml is not None:
                import lxml.etree
                raw_xml = lxml.etree.tostring(manifest_xml, pretty_print=True, encoding="utf-8").decode(
                    "utf-8", errors="replace"
                )
                components = self._extract_components_from_xml(
                    manifest_xml, apk_obj.get_target_sdk_version()
                )
        except Exception as e:
            logger.debug(f"Could not convert manifest XML or components: {e}")

        return ManifestData(
            package_name=package_name,
            app_name=app_name,
            version_name=apk_obj.get_androidversion_name(),
            version_code=apk_obj.get_androidversion_code(),
            min_sdk=apk_obj.get_min_sdk_version(),
            target_sdk=apk_obj.get_target_sdk_version(),
            allow_backup=allow_backup,
            debuggable=debuggable,
            uses_cleartext_traffic=uses_cleartext,
            network_security_config=net_sec_config,
            raw_xml=raw_xml,
            components=components,
        )

    def _extract_components_from_xml(
        self, manifest_xml: Any, target_sdk_raw: Any
    ) -> list[Any]:
        """Extract activities, services, receivers, and providers with export status."""
        from data_leak_detector.core.models import ComponentDetail

        target_sdk = None
        try:
            if target_sdk_raw is not None:
                target_sdk = int(str(target_sdk_raw).strip())
        except (ValueError, TypeError):
            pass

        components: list[ComponentDetail] = []
        ns = "http://schemas.android.com/apk/res/android"

        for tag in ("activity", "service", "receiver", "provider"):
            for elem in manifest_xml.iter(tag):
                name = elem.get(f"{{{ns}}}name") or elem.get("name")
                if not name:
                    continue

                exported_attr = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                perm = elem.get(f"{{{ns}}}permission") or elem.get("permission")
                read_perm = elem.get(f"{{{ns}}}readPermission") or elem.get("readPermission")
                write_perm = elem.get(f"{{{ns}}}writePermission") or elem.get("writePermission")

                intent_filters = list(elem.iter("intent-filter"))
                has_filter = len(intent_filters) > 0

                is_launcher = False
                actions: list[str] = []
                for ifilter in intent_filters:
                    act_names = [
                        a.get(f"{{{ns}}}name") or a.get("name")
                        for a in ifilter.iter("action")
                    ]
                    cat_names = [
                        c.get(f"{{{ns}}}name") or c.get("name")
                        for c in ifilter.iter("category")
                    ]
                    actions.extend([a for a in act_names if a])
                    if (
                        "android.intent.action.MAIN" in act_names
                        and "android.intent.category.LAUNCHER" in cat_names
                    ):
                        is_launcher = True

                if exported_attr is not None:
                    is_exported = str(exported_attr).strip().lower() in ("true", "1")
                else:
                    if tag == "provider":
                        is_exported = target_sdk is not None and target_sdk < 17
                    else:
                        is_exported = has_filter

                components.append(
                    ComponentDetail(
                        component_type=tag,
                        name=name,
                        exported=is_exported,
                        permission=perm,
                        read_permission=read_perm,
                        write_permission=write_perm,
                        has_intent_filter=has_filter,
                        is_main_launcher=is_launcher,
                        actions=actions,
                    )
                )

        return components

    def _parse_bool_attribute(self, apk_obj: Any, tag: str, attr: str) -> bool | None:
        """Safely fetch and parse boolean attribute from APK manifest."""
        try:
            val = apk_obj.get_attribute_value(tag, attr)
            if val is None:
                return None
            val_str = str(val).strip().lower()
            if val_str in ("true", "1"):
                return True
            if val_str in ("false", "0"):
                return False
        except Exception:
            pass
        return None
