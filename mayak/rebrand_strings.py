# Маяк: названия внутри приложения. Меняем исходную строку в коде и в <source> всех .ts одинаково
# (иначе перевод не найдётся), а русский перевод задаём сами.
import glob, re, sys
from xml.sax.saxutils import escape

ITEMS = [
    # (файл, исходная строка как в коде, новая исходная, русский перевод)
    ("ui/utils/notificationHandler.cpp", 'AmneziaVPN', 'Mayak VPN', 'Маяк VPN'),
    ("ui/utils/notificationHandler.cpp", 'AmneziaVPN notification', 'Mayak VPN notification', 'Уведомление Маяк VPN'),
    ("ui/qml/Pages2/PageSettings.qml", 'About AmneziaVPN', 'About Mayak VPN', 'О приложении Маяк VPN'),
    ("ui/qml/Pages2/PageSettingsAbout.qml", 'You have the latest version of AmneziaVPN', 'You have the latest version of Mayak VPN',
     'У вас последняя версия Маяк VPN'),
    ("core/utils/errorStrings.cpp", 'Amnezia helper service error', 'Mayak VPN helper service error', 'Ошибка вспомогательной службы Маяк VPN'),
    ("core/utils/errorStrings.cpp",
     "Your Amnezia Premium subscription has expired.\\n Please check your email for renewal instructions.\\n If you haven't received an email, please contact our support.",
     "Your Mayak VPN access has expired.\\n Please contact the administrator to renew it.",
     'Срок доступа к Маяк VPN закончился.\nНапишите администратору, чтобы продлить.'),
]

def ts_text(code_str):
    # строка из исходника → как она записана в .ts
    return escape(code_str.replace('\\n', '\n'), {"'": "&apos;", '"': "&quot;"})

changed = 0
for path, old, new, ru in ITEMS:
    s = open(path, encoding='utf-8').read()
    lit_old, lit_new = '"' + old + '"', '"' + new + '"'
    n = s.count(lit_old)
    if n == 0:
        sys.exit(f"не найдено в {path}: {old[:60]}")
    s = s.replace(lit_old, lit_new)
    open(path, 'w', encoding='utf-8').write(s)
    for ts in glob.glob('translations/*.ts'):
        t = open(ts, encoding='utf-8').read()
        src_old, src_new = f'<source>{ts_text(old)}</source>', f'<source>{ts_text(new)}</source>'
        if src_old not in t:
            continue
        t = t.replace(src_old, src_new)
        if ts.endswith('_ru_RU.ts'):
            t = re.sub(r'(' + re.escape(src_new) + r'\s*<translation)[^>]*>.*?(</translation>)',
                       lambda m: m.group(1) + '>' + escape(ru) + m.group(2), t, flags=re.S)
        open(ts, 'w', encoding='utf-8').write(t)
    changed += n
print("заменено в коде:", changed)
