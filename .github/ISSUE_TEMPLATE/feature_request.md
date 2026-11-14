name: Feature request
description: A scanner, detection class, or UI improvement
labels: [enhancement]
body:
  - type: textarea
    id: what
    attributes:
      label: What should Aegis SS detect or display
    validations:
      required: true
  - type: textarea
    id: falsepositives
    attributes:
      label: Expected false positive behavior
      description: Be explicit. What benign things must not fire this check.
    validations:
      required: true
  - type: dropdown
    id: elevation
    attributes:
      label: Needs admin
      options:
        - No
        - Yes
        - Optional with degradation
    validations:
      required: true
  - type: checkboxes
    id: keep
    attributes:
      label: Guarantee preservation
      options:
        - label: This keeps the tool read only
        - label: This adds no network capability
