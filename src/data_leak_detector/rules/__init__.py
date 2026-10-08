"""Rule definitions and execution registry for static detection of data leakage."""

from data_leak_detector.rules.base import BaseRule
from data_leak_detector.rules.manifest_rules import (
    ALL_MANIFEST_RULES,
    AllowBackupRule,
    CleartextTrafficPermittedRule,
    DebuggableRule,
    ExcessivePermissionCombinationRule,
    ExportedActivityRule,
    ExportedProviderRule,
    ExportedReceiverRule,
    ExportedServiceRule,
    NetworkSecurityConfigRule,
    SensitiveComponentExposureRule,
)
from data_leak_detector.rules.secret_rules import (
    ALL_SECRET_RULES,
    AwsCredentialRule,
    DatabaseCredentialRule,
    GenericApiTokenRule,
    GoogleApiKeyRule,
    HardcodedPasswordRule,
    HardcodedSecretRule,
    OAuthClientSecretRule,
    PrivateKeyMaterialRule,
)
from data_leak_detector.rules.crypto_rules import (
    ALL_CRYPTO_RULES,
    BrokenCipherRule,
    EcbModeCipherRule,
    HardcodedCryptoKeyRule,
    InsecureContextHashRule,
    InsecureRandomSeedRule,
    StaticOrWeakIvRule,
    WeakCryptoRule,
)
from data_leak_detector.rules.network_rules import (
    ALL_NETWORK_RULES,
    CleartextHttpUrlRule,
    CleartextTrafficConfigRule,
    CleartextTrafficRule,
    InsecureWebViewNetworkRule,
    PermissiveHostnameVerifierRule,
    SslValidationBypassRule,
    ThirdPartyEndpointRule,
    TrackingAndAdEndpointRule,
    TrustAllCertificatesRule,
)
from data_leak_detector.rules.registry import RuleExecutionReport, RuleRegistry
from data_leak_detector.rules.sdk_rules import (
    ALL_SDK_RULES,
    SdkPermissionExposureRule,
    ThirdPartySdkIdentificationRule,
    ThirdPartyTrackerRule,
)
from data_leak_detector.rules.storage_rules import (
    ALL_STORAGE_RULES,
    ExternalStorageSensitiveDataRule,
    InsecureStorageRule,
    PlaintextDatabaseSensitiveDataRule,
    PlaintextSharedPreferencesRule,
    SensitiveCacheStorageRule,
    SensitiveInformationLoggingRule,
    WorldReadableWritableStorageRule,
)



__all__ = [
    "BaseRule",
    "RuleRegistry",
    "RuleExecutionReport",
    "ALL_MANIFEST_RULES",
    "ALL_SECRET_RULES",
    "ALL_NETWORK_RULES",
    "ALL_STORAGE_RULES",
    "ALL_CRYPTO_RULES",
    "ALL_SDK_RULES",
    "CleartextHttpUrlRule",
    "CleartextTrafficRule",
    "CleartextTrafficConfigRule",
    "TrustAllCertificatesRule",
    "PermissiveHostnameVerifierRule",
    "SslValidationBypassRule",
    "InsecureWebViewNetworkRule",
    "TrackingAndAdEndpointRule",
    "ThirdPartyEndpointRule",
    "WorldReadableWritableStorageRule",
    "InsecureStorageRule",
    "ExternalStorageSensitiveDataRule",
    "PlaintextSharedPreferencesRule",
    "PlaintextDatabaseSensitiveDataRule",
    "SensitiveInformationLoggingRule",
    "SensitiveCacheStorageRule",
    "BrokenCipherRule",
    "WeakCryptoRule",
    "EcbModeCipherRule",
    "StaticOrWeakIvRule",
    "HardcodedCryptoKeyRule",
    "InsecureContextHashRule",
    "InsecureRandomSeedRule",
    "ThirdPartySdkIdentificationRule",
    "ThirdPartyTrackerRule",
    "SdkPermissionExposureRule",
]
