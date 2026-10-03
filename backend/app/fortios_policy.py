"""Keep VIP identity separate from its mapped IP during policy evaluation."""
from .models import CanonicalConfig, Confidence
from .reachability_models import NatEffect


def fortios_policy_view(config: CanonicalConfig, effects: list[NatEffect]) -> CanonicalConfig:
    if config.device.network_os != "fortios":
        return config
    names = {effect.name for effect in effects if effect.applied and effect.stage == "destination"}
    policies = []
    for policy in config.policies:
        if policy.destination_vips and (policy.dst_negate or not policy.vip_only or config.device.features.get("central_nat")):
            # VIP identities cannot be complemented/combined as ordinary IPs.
            # Preserve the uncertain rule instead of falling through to ALLOW.
            policies.append(policy.model_copy(update={"dst": ["any"], "dst_negate": False,
                                                       "confidence": Confidence.PARTIAL}))
            continue
        if config.device.features.get("central_nat"):
            policies.append(policy)
            continue
        if policy.vip_only:
            if not names.intersection(policy.destination_vips):
                continue
        elif names:
            if policy.action == "permit" and not policy.destination_vips:
                continue
            if policy.match_vip is False:
                continue
            if policy.match_vip is None:
                policy = policy.model_copy(update={"confidence": Confidence.PARTIAL})
        policies.append(policy)
    return config.model_copy(update={"policies": policies})
