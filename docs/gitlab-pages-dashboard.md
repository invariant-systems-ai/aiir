# GitLab Pages Dashboard — AIIR Receipt History

> Deploy a static dashboard showing AI authorship trends, receipt history,
> and authorship class breakdown for your project.

## Quick Setup

Add this job to your `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - deploy

# Generate receipts (prerequisite)
aiir-receipt:
  stage: test
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    - aiir --pretty --gitlab-ci --output .aiir-receipts/
  artifacts:
    paths:
      - .aiir-receipts/
    expire_in: 30 days

# Deploy dashboard to GitLab Pages
pages:
  stage: deploy
  image: python:3.11-slim
  dependencies:
    - aiir-receipt
  script:
    - pip install --quiet aiir
    - mkdir -p public
    - |
      python3 -c "
      import json, glob
      from aiir._gitlab import generate_dashboard_html

      receipts = []
      for f in sorted(glob.glob('.aiir-receipts/*.json')):
          with open(f) as fh:
              receipts.append(json.load(fh))

      html = generate_dashboard_html(receipts, project_name='${CI_PROJECT_NAME}')
      with open('public/index.html', 'w') as fh:
          fh.write(html)
      print(f'Dashboard generated: {len(receipts)} receipts')
      "
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## What you get

The dashboard shows:

- **Summary cards**: Total receipts, AI-authored count/%, human count, bot count
- **Authorship breakdown table**: Count and percentage per class (human, ai_assisted, bot, ai+bot)
- **Recent receipts table**: Last 50 receipts with commit SHA, subject, class, and timestamp

The dashboard auto-deploys to `https://<group>.gitlab.io/<project>/` on
every push to the default branch.

## Full-history dashboard

For a one-time full-repo audit:

```yaml
pages:
  stage: deploy
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    - mkdir -p public .aiir-receipts
    # Receipt the entire repo history
    - aiir --range "$(git rev-list --max-parents=0 HEAD)..HEAD" --output .aiir-receipts/ --pretty
    - |
      python3 -c "
      import json, glob
      from aiir._gitlab import generate_dashboard_html

      receipts = []
      for f in sorted(glob.glob('.aiir-receipts/*.json')):
          with open(f) as fh:
              receipts.append(json.load(fh))

      html = generate_dashboard_html(receipts, project_name='${CI_PROJECT_NAME}')
      with open('public/index.html', 'w') as fh:
          fh.write(html)
      print(f'Dashboard generated: {len(receipts)} receipts')
      "
  artifacts:
    paths:
      - public
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
```

## Using the CI/CD Catalog component

If you're already using the AIIR Catalog component, just add the Pages
job after it:

```yaml
include:
  - component: gitlab.com/invariant-systems/aiir/receipt@1
    inputs:
      stage: test

pages:
  stage: deploy
  image: python:3.11-slim
  dependencies:
    - aiir-receipt-push
  script:
    - pip install --quiet aiir
    - mkdir -p public
    - |
      python3 << 'PYEOF'
      import json, glob
      from aiir._gitlab import generate_dashboard_html
      receipts = []
      for f in sorted(glob.glob('.aiir-receipts/*.json')):
          with open(f) as fh:
              receipts.append(json.load(fh))
      html = generate_dashboard_html(receipts, project_name='$CI_PROJECT_NAME')
      with open('public/index.html', 'w') as fh:
          fh.write(html)
      PYEOF
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

**Links**: [AIIR on PyPI](https://pypi.org/project/aiir/) ·
[GitLab Pages](https://docs.gitlab.com/ee/user/project/pages/) ·
[AIIR GitLab CI/CD Component](https://gitlab.com/explore/catalog/invariant-systems/aiir)
