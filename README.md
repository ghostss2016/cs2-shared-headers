# cs2-shared-headers — единый источник шаред-интерфейсов
Канон IUtilsApi = 43 слота (HookOnTakeDamage @ slot35), совпадает с деплоенной utils.so.
Расхождение menus.h по плагинам ломало vtable -> краш при смене карты. CI build.sh перезаписывает
локальные menus.h/sql_mm.h/mysql_mm.h этими. Обновлять ТОЛЬКО тут.
