# Specter Brand Guide

Specter ist ein seriöses B2B-SaaS-/Security-System. Die Marke soll nicht verspielt wirken, sondern zuverlässig, technisch, sauber und auditierbar.

## Logo-Dateien

Alle Marken-Assets liegen unter `docs/brand/`:

- `docs/brand/specter-logo.svg` – Hauptlogo für helle Hintergründe
- `docs/brand/specter-logo-white.svg` – Logo für dunkle Hintergründe ohne Fläche
- `docs/brand/specter-logo-reversed.svg` – Logo auf dunkler Markenfläche
- `docs/brand/specter-mark.svg` – Icon/Marke ohne Wortmarke
- `docs/brand/specter-mark-mono.svg` – einfarbige Version für Sonderfälle
- `docs/brand/favicon.svg` – Favicon/App-Icon-Basis

## Farben

| Token | Hex | Nutzung |
|---|---:|---|
| Deep Navy | `#0D1B2A` | Hauptfarbe, Header, Wordmark, Security-Feeling |
| Charcoal | `#1F2937` | Text, sekundäre Flächen, technische UI |
| Teal | `#14B8A6` | Akzent, Status, Highlights, Trust-Signal |
| Light Gray | `#F3F4F6` | Hintergrund, Karten, Border-Kontrast |
| White | `#FFFFFF` | Negativflächen, Dark-Mode-Kontrast |

## Einsatzregeln

1. Hauptlogo auf weißen oder sehr hellen Hintergründen verwenden.
2. Auf dunklen Flächen `tone="light"` oder `specter-logo-white.svg` verwenden.
3. Das Mark/Icon nur verwenden, wenn der Kontext bereits klar macht, dass es um Specter geht.
4. Keine Schatten, 3D-Effekte, Glow-Effekte oder Gaming-Optik hinzufügen.
5. Genug Abstand lassen: mindestens die halbe Logo-Mark-Höhe rund um das Logo.
6. Keine Farben außerhalb der Markenpalette für das Logo verwenden.

## Optionales Web-Frontend (falls später eine UI entsteht)

Specter ist aktuell ein Python-CLI-Tool ohne Web-Oberfläche. Sollte später ein
Web-Frontend (z. B. React/Next.js) für Berichte entstehen, lassen sich die
SVG-Assets direkt einbinden, z. B.:

```tsx
export const metadata = {
  title: "Specter",
  description: "Defensiver, scope-gebundener Sicherheits-Agent für Firmenumgebungen.",
  icons: { icon: "/brand/favicon.svg" },
};
```
