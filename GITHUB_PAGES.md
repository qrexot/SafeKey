# GitHub Pages

Проект уже статический (HTML/CSS/JS), поэтому сборка не нужна.

В репозитории подготовлена папка `docs/` — GitHub Pages будет раздавать сайт именно из неё.

## Как включить

1. Запушьте репозиторий в GitHub (ветка `main` или `master`)
2. Откройте: `Settings` → `Pages`
3. В блоке `Build and deployment` выберите `Source: Deploy from a branch`
4. Выберите `Branch: main` (или `master`) и `Folder: /docs`

Через минуту сайт будет доступен по адресу:
`https://<username>.github.io/<repo>/`

## Примечания

- В `docs/` добавлен файл `.nojekyll`, чтобы GitHub Pages не пытался обрабатывать сайт через Jekyll.
- Для SPA-навигации добавлен `docs/404.html` (копия `index.html`).

