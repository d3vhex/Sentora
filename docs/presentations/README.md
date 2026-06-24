# DTCloud Meeting Pack

Three documents tailored for the DTCloud kick-off conversation:

| File | Purpose | Audience |
| :--- | :--- | :--- |
| [`00-pitch-deck.md`](00-pitch-deck.md) | 30-slide Marp deck. Product overview, architecture, AI pipeline, Shadow Mode, production sizing, update model, pricing, roadmap, POC plan. | Mixed (CTO + CISO + DevOps) |
| [`production-deployment.md`](production-deployment.md) | Operational runbook: sizing, network topology, TLS, backup, monitoring, air-gap. | SecOps + DevOps engineer |
| [`update-runbook.md`](update-runbook.md) | Upgrade procedure: versioning policy, server upgrade, agent rollout, rollback, breaking-change policy. | Same as above |

## Rendering the deck

Marp is the simplest way to turn `00-pitch-deck.md` into a presentation.

### Option A: VS Code (interactive)

```
ext install marp-team.marp-vscode
```

Open `00-pitch-deck.md`, click the Marp preview icon. Live edit while
talking.

### Option B: CLI export (PDF / PPTX / HTML)

```bash
npm install -g @marp-team/marp-cli

# PDF for emailing
marp 00-pitch-deck.md --pdf -o sentora-dtcloud.pdf

# PPTX if DTCloud prefers PowerPoint
marp 00-pitch-deck.md --pptx -o sentora-dtcloud.pptx

# Self-contained HTML for offline laptop demo
marp 00-pitch-deck.md --html -o sentora-dtcloud.html
```

The deck references screenshots in `../pics/`. Marp resolves relative
paths fine, no extra step needed.

### Option C: Docker (no Node install)

```bash
docker run --rm -v "$PWD":/home/marp/app -e MARP_USER=$(id -u):$(id -g) \
    marpteam/marp-cli 00-pitch-deck.md --pdf -o sentora-dtcloud.pdf
```

## Customising

- **Branding:** edit the `<style>` block at the top of `00-pitch-deck.md`.
  Hex colours are tuned for a dark presentation; light theme is one
  swap away.
- **Audience focus:** if you only have 15 minutes, hide the architecture
  deep-dive slides (everything between "Component topology" and
  "Per-agent enrolment") and the roadmap detail.
- **POC numbers:** the closing "Önerilen DTCloud POC akışı" slide is
  generic. Tailor weekly milestones to the actual scope agreed on the
  call.

## Reviewing before the meeting

```bash
# Spell-check
aspell --lang=en check 00-pitch-deck.md

# Word count (rough timing check, 130-150 wpm spoken)
wc -w 00-pitch-deck.md
```

A 30-slide deck typically runs 25 to 35 minutes plus Q&A. Time-box the
deeper slides; if the audience is sales-leaning, breeze through "AI
pipeline detayı" and "Defensive autonomy allow-list".
