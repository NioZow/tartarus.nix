# Guest naming: `kind` collapses the old vm-/ctn- prefixing, and the instance
# suffix is passed in explicitly (the impure MICROVM_INSTANCE_SUFFIX /
# CONTAINER_INSTANCE_SUFFIX env reads stay in the builder, not here).
{lib}: let
  kindPrefix = kind:
    if kind == "vm"
    then "vm"
    else "ctn";

  # nixosConfigurations / package attribute name for a guest, e.g. vm-vault.
  namespace = kind: name: "${kindPrefix kind}-${name}";

  isNamespaced = kind: name: lib.hasPrefix "${kindPrefix kind}-" name;

  baseName = kind: name: lib.removePrefix "${kindPrefix kind}-" name;

  # Numbered/ad-hoc instances append a suffix; the empty suffix is canonical.
  instanceName = name: suffix:
    if suffix == ""
    then name
    else "${name}-${suffix}";

  instanceSuffixEnvVar = kind:
    if kind == "vm"
    then "MICROVM_INSTANCE_SUFFIX"
    else "CONTAINER_INSTANCE_SUFFIX";
in {
  inherit
    kindPrefix
    namespace
    isNamespaced
    baseName
    instanceName
    instanceSuffixEnvVar
    ;
}
