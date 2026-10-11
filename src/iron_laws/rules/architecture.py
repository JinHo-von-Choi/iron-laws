"""architecture 규칙의 공개 import와 카탈로그 호환층."""


























from iron_laws.rules.architecture_common import (
    CENTRAL_ERROR_FILE as CENTRAL_ERROR_FILE,
)
from iron_laws.rules.architecture_common import (
    DB_IMPORT_RE as DB_IMPORT_RE,
)
from iron_laws.rules.architecture_common import (
    DB_READ as DB_READ,
)
from iron_laws.rules.architecture_common import (
    DB_RECEIVER as DB_RECEIVER,
)
from iron_laws.rules.architecture_common import (
    DB_WRITE as DB_WRITE,
)
from iron_laws.rules.architecture_common import (
    EXCEPTION_CALLEE as EXCEPTION_CALLEE,
)
from iron_laws.rules.architecture_common import (
    FUNCTION_TYPE_SET as FUNCTION_TYPE_SET,
)
from iron_laws.rules.architecture_common import (
    GENERATED_RE as GENERATED_RE,
)
from iron_laws.rules.architecture_common import (
    IMPORT_PATTERNS as IMPORT_PATTERNS,
)
from iron_laws.rules.architecture_common import (
    JS_IMPORT as JS_IMPORT,
)
from iron_laws.rules.architecture_common import (
    KEY_CALLEE as KEY_CALLEE,
)
from iron_laws.rules.architecture_common import (
    LAYER_DIR_TOKENS as LAYER_DIR_TOKENS,
)
from iron_laws.rules.architecture_common import (
    LAYER_FILE_PATTERNS as LAYER_FILE_PATTERNS,
)
from iron_laws.rules.architecture_common import (
    LAYER_LABEL as LAYER_LABEL,
)
from iron_laws.rules.architecture_common import (
    LAYER_RANK as LAYER_RANK,
)
from iron_laws.rules.architecture_common import (
    LOOP_NODE_TYPES as LOOP_NODE_TYPES,
)
from iron_laws.rules.architecture_common import (
    MAPPING_ONLY_RE as MAPPING_ONLY_RE,
)
from iron_laws.rules.architecture_common import (
    REQUEST_HOOK_NAMES as REQUEST_HOOK_NAMES,
)
from iron_laws.rules.architecture_common import (
    REUSABLE_PATTERNS as REUSABLE_PATTERNS,
)
from iron_laws.rules.architecture_common import (
    STANDARD_HEADER_RE as STANDARD_HEADER_RE,
)
from iron_laws.rules.architecture_common import (
    WEB_IMPORT_RE as WEB_IMPORT_RE,
)
from iron_laws.rules.architecture_common import (
    ArchRule as ArchRule,
)
from iron_laws.rules.architecture_common import (
    _is_generated as _is_generated,
)
from iron_laws.rules.architecture_common import (
    external_imports as external_imports,
)
from iron_laws.rules.architecture_common import (
    infer_layer as infer_layer,
)
from iron_laws.rules.architecture_practices import (
    AttributeKeyRule as AttributeKeyRule,
)
from iron_laws.rules.architecture_practices import (
    DbInLoopRule as DbInLoopRule,
)
from iron_laws.rules.architecture_practices import (
    DtoMapMixRule as DtoMapMixRule,
)
from iron_laws.rules.architecture_practices import (
    ErrorMessageScatterRule as ErrorMessageScatterRule,
)
from iron_laws.rules.architecture_practices import (
    RepeatedLiteralRule as RepeatedLiteralRule,
)
from iron_laws.rules.architecture_practices import (
    ReusableObjectRule as ReusableObjectRule,
)
from iron_laws.rules.architecture_structure import (
    CircularDependencyRule as CircularDependencyRule,
)
from iron_laws.rules.architecture_structure import (
    DuplicateHelperRule as DuplicateHelperRule,
)
from iron_laws.rules.architecture_structure import (
    LayerDirectionRule as LayerDirectionRule,
)
from iron_laws.rules.architecture_structure import (
    LayeringRule as LayeringRule,
)
from iron_laws.rules.architecture_structure import (
    NoTestsRule as NoTestsRule,
)
from iron_laws.rules.architecture_structure import (
    SizeAndComplexityRule as SizeAndComplexityRule,
)
from iron_laws.rules.base import BaseRule

ARCH_RULES: list[type[BaseRule]] = [
    SizeAndComplexityRule,
    LayeringRule,
    CircularDependencyRule,
    DuplicateHelperRule,
    RepeatedLiteralRule,
    NoTestsRule,
    LayerDirectionRule,
    DtoMapMixRule,
    ErrorMessageScatterRule,
    AttributeKeyRule,
    ReusableObjectRule,
    DbInLoopRule,
]
