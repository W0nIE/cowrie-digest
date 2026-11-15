---
name: Задача
description: Новая задача для доски (спецификация перед разработкой)
title: ""
labels: []
body:
  - type: textarea
    id: goal
    attributes:
      label: Цель
      description: Что должно получиться
  - type: textarea
    id: context
    attributes:
      label: Контекст
      description: Текущее состояние, зачем задача
  - type: textarea
    id: solution
    attributes:
      label: Предлагаемое решение
      description: План реализации, затрагиваемые файлы
  - type: textarea
    id: acceptance
    attributes:
      label: Acceptance criteria
      description: Проверяемые критерии готовности
  - type: textarea
    id: out_of_scope
    attributes:
      label: Out of scope
      description: Что явно НЕ делаем
  - type: textarea
    id: questions
    attributes:
      label: Открытые вопросы
      description: Что уточнить у пользователя
---
