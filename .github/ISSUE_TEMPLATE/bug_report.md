name: Bug report
description: A finding, crash, or UI problem in Aegis SS
labels: [bug]
body:
  - type: input
    id: version
    attributes:
      label: Version and hash
      placeholder: aegis-ss v1.0.0. SHA256 from certutil -hashfile aegis-ss.exe SHA256
    validations:
      required: true
  - type: dropdown
    id: elevation
    attributes:
      label: Elevation mode
      options:
        - Standard user
        - Administrator
    validations:
      required: true
  - type: textarea
    id: what
    attributes:
      label: What happened
      description: Paste the module output and the exact UTC timestamp if known
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: What should have happened
    validations:
      required: true
  - type: checkboxes
    id: falsepositive
    attributes:
      label: If this is a false positive
      options:
        - label: I included the raw module evidence, not just the summary line
