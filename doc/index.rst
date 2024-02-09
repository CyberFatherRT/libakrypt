.. documentation master file, created by
   sphinx-quickstart on Sun Apr 17 02:37:11 2022.

Проект libakrypt
================

Целью проекта **libakrypt** является разработка и продвижение свободно распространяемых программных средств защиты информации,
удовлетворяющих рекомендациям по стандартизации [P1323565.1.012-2017]_ .
Проект реализуется на языке Си и
распространяется под лицензией `MIT <https://git.miem.hse.ru/axelkenzo/libakrypt-0.x/-/raw/master/LICENSE>`__.

.. note::
  Последняя версия исходных текстов библиотеки может быть скачана
  с сайта: `https://git.miem.hse.ru/axelkenzo/libakrypt-0.x <https://git.miem.hse.ru/axelkenzo/libakrypt-0.x>`__


В состав проекта входят:

- библиотеки **libakrypt** и **libakrypt-base**, реализующие базовые преобразования
  в соответствии с российскими стандартами и рекомендациями по стандартизации в области криптографической защиты информации,
- утилита **aktool**, предназначенная для выработки ключевой информации и криптографического преобразования информации
  в пространстве пользователя.


.. toctree::
   :caption: Пользователям
   :maxdepth: 3

   annotation.rst
   install-guide.rst
   faq.rst
   aktool.rst
   API функций библиотеки <https://libakrypt.ru/api/topics.html>

.. toctree::
   :maxdepth: 2
   :caption: Разработчикам

   bibliography.rst

Дополнительные файлы для скачивания
-----------------------------------

- Документация в формате :download:`pdf <https://libakrypt.ru/api/akrypt-library.pdf>`.
- API функций библиотеки в формате :download:`qch <https://libakrypt.ru/api/akrypt-library.qch>`.
