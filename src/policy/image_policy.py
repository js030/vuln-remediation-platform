import os

import yaml


def load_image_policy(policy_file: str) -> dict:
    """Load the central team-approved image policy YAML file."""
    if not os.path.exists(policy_file):
        raise FileNotFoundError(
            f"Image policy file does not exist: {policy_file}"
        )

    with open(policy_file, "r", encoding="utf-8") as file:
        policy = yaml.safe_load(file) or {}

    if not isinstance(policy, dict) or "images" not in policy:
        raise ValueError(
            "Invalid policy file: top-level key 'images' is required."
        )

    if not isinstance(policy["images"], dict):
        raise ValueError(
            "Invalid policy file: 'images' must be a mapping."
        )

    return policy


def split_image_reference(image_ref: str) -> tuple[str, str | None]:
    """
    Split an image reference into repository and tag.

    Examples:
      nginx:1.14.0
        -> ("nginx", "1.14.0")

      prom/node-exporter:v1.0.1
        -> ("prom/node-exporter", "v1.0.1")

      registry.example.local/team/app:1.2.3
        -> ("registry.example.local/team/app", "1.2.3")

      nginx@sha256:abc123
        -> ("nginx", None)
    """
    if "@" in image_ref:
        repository = image_ref.split("@", 1)[0]
        return repository, None

    last_slash = image_ref.rfind("/")
    last_colon = image_ref.rfind(":")

    if last_colon > last_slash:
        return image_ref[:last_colon], image_ref[last_colon + 1:]

    return image_ref, None


def select_approved_target(
    original_image: str,
    policy: dict,
) -> tuple[str | None, str, dict | None]:
    """
    Select the team-approved target image based on the repository.

    Examples:
      nginx:1.14.0 -> policy key nginx -> nginx:1.24.0
      nginx:1.20.2 -> policy key nginx -> nginx:1.24.0

    This replaces the old exact mapping:
      nginx:1.14.0 -> nginx:1.24.0
    """
    repository, _ = split_image_reference(original_image)

    image_policy = policy.get("images", {}).get(repository)

    if not image_policy:
        return None, f"repository_not_in_policy:{repository}", None

    approved_image = image_policy.get("approved_image")

    if not approved_image:
        return None, "policy_has_no_approved_image", image_policy

    if approved_image == original_image:
        return None, "already_using_approved_image", image_policy

    return approved_image, "team_approved_baseline", image_policy
