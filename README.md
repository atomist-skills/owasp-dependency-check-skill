# `atomist/owasp-dependency-check`

Scan projects using
[OWasp Dependency Check](https://owasp.org/www-project-dependency-check/).

By default, detect pushes to repositories containing scannable projects. Scan
the project dependencies and create a GitHub CheckRun with the scan results.

![image](docs/images/CheckRun.png)

This creates consistent checks across all scannable repos.

### Model

![model](https://lucid.app/publicSegments/view/e9bde885-6b28-46da-8519-218665a07916/image.png)

Transact the evidence, which can be package url, or CPE based, that a project
depends on some open source library. We also track the current mappings of CPEs,
and package urls, to vulnerabilities. Although this changes over time. Our
vulnerability risk assessment changes over time.

We also transact a discovery event when we've finished scanning a project a
repo.

### Prerequisistes

-   GitHub app installation - we need an authorized installation to create check
    runs and to clone head commits that need scanning.
-   File indexer Skill - this skill activates when we discover certain kinds of
    project files in repos
-   Maven capability - scanning relies on credentials for private registries
-   NVD mirror - maintain a synchronized db of NVD

---

Created by [Atomist][atomist]. Need Help? [Join our Slack workspace][slack].

[atomist]: https://atomist.com/ "Atomist - How Teams Deliver Software"
[slack]: https://join.atomist.com/ "Atomist Community Slack"
