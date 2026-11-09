.pragma library

// Source: reference/mayak-visual-v1/content/cities.json and city-assets/ATTRIBUTIONS.md.
// Only an explicit selected-exit cityId plus candidateId reveals a city.
var oslo = {
    id: "oslo", location: "Norway/Oslo", title: "Вы в Осло, в Норвегии",
    shortText: "Город на берегу фьорда, где по крыше Оперы можно дойти до самой воды.",
    paragraphs: [
        "Осло стоит в глубине Осло-фьорда и окружён лесистыми холмами: от центра до леса можно доехать на метро, а до островов — на пароме.",
        "Город основан в XI веке, но сегодня его узнают по современной набережной Бьёрвика: здание Оперы с наклонной мраморной крышей открылось в 2008 году, рядом — новый музей Мунка.",
        "Зимой здесь катаются на лыжах прямо в черте города, а летом купаются во фьорде."
    ],
    sights: [
        ["Опера", "Можно подняться по крыше и смотреть на фьорд."],
        ["Музей Мунка", "Крупнейшее собрание работ Эдварда Мунка."],
        ["Парк Вигеланна", "Более двухсот скульптур Густава Вигеланна под открытым небом."]
    ],
    photo: "qrc:/ui/qml/MayakCity/oslo.jpg", photoTitle: "Oslo Opera House at night",
    author: "Samthecrazyman", license: "CC BY-SA 4.0", source: "Wikimedia Commons",
    licenseUrl: "https://creativecommons.org/licenses/by-sa/4.0/",
    sourceUrl: "https://commons.wikimedia.org/wiki/File:PXL_20260429_223319897.NIGHT.RAW-01.COVER.jpg"
}

var helsinki = {
    id: "helsinki", location: "Finland/Helsinki", title: "Вы в Хельсинки, в Финляндии",
    shortText: "Морская столица с белым собором над Сенатской площадью и крепостью на островах.",
    paragraphs: [
        "Хельсинки основал шведский король Густав Васа в 1550 году, а столицей Финляндии город стал в 1812-м.",
        "Центр города — Сенатская площадь и белый кафедральный собор архитектора Энгеля. Рядом с гаванью стоит краснокирпичный Успенский собор.",
        "Город живёт морем: на островах — крепость Суоменлинна, а в общественных саунах на берегу после пара прыгают в Балтику даже зимой."
    ],
    sights: [
        ["Суоменлинна", "Морская крепость XVIII века на островах, объект ЮНЕСКО."],
        ["Библиотека Ооди", "Открыта в 2018 году: книги, студии, 3D-принтеры и швейные машины для всех."],
        ["Сенатская площадь", "Ансамбль в стиле ампир и собор на вершине лестницы."]
    ],
    photo: "qrc:/ui/qml/MayakCity/helsinki.jpg", photoTitle: "Helsinki Cathedral at night",
    author: "Leonhard Lenz", license: "CC0 1.0", source: "Wikimedia Commons",
    licenseUrl: "https://creativecommons.org/publicdomain/zero/1.0/",
    sourceUrl: "https://commons.wikimedia.org/wiki/File:Helsingin_tuomiokirkko_at_night_2022-09-18_01.jpg"
}

var amsterdam = {
    id: "amsterdam", location: "Netherlands/Amsterdam", title: "Вы в Амстердаме, в Нидерландах",
    shortText: "Город каналов XVII века, узких домов с фронтонами и велосипедов на каждом мосту.",
    paragraphs: [
        "Пояс каналов Амстердама прорыли в XVII веке, в Золотой век Нидерландов, а в 2010 году он вошёл в список всемирного наследия ЮНЕСКО.",
        "Через каналы перекинуто больше полутора тысяч мостов, а узкие дома с фронтонами строили так из-за налога на ширину фасада.",
        "Велосипед здесь — главный транспорт: их в городе больше, чем жителей."
    ],
    sights: [
        ["Рейксмузеум", "«Ночной дозор» Рембрандта и голландская живопись."],
        ["Музей Ван Гога", "Крупнейшее собрание работ художника."],
        ["Дом Анны Франк", "Убежище, где был написан знаменитый дневник."]
    ],
    photo: "qrc:/ui/qml/MayakCity/amsterdam.jpg", photoTitle: "Amsterdam Grachten at night",
    author: "GillyBerlin", license: "CC BY 2.0", source: "Wikimedia Commons",
    licenseUrl: "https://creativecommons.org/licenses/by/2.0/",
    sourceUrl: "https://commons.wikimedia.org/wiki/File:Amsterdam_Grachten_at_night.jpg"
}

var frankfurt = {
    id: "frankfurt", location: "Germany/Frankfurt", title: "Вы во Франкфурте, в Германии",
    shortText: "Финансовая столица Европы с небоскрёбами над Майном и родной город Гёте.",
    paragraphs: [
        "Из-за небоскрёбов над рекой Майн Франкфурт в шутку называют Майнхэттеном. Здесь находится Европейский центральный банк.",
        "В 1749 году во Франкфурте родился Гёте — его дом-музей стоит в центре. Каждую осень здесь проходит крупнейшая в мире книжная ярмарка.",
        "Для интернета Франкфурт особенный: здесь работает DE-CIX, одна из крупнейших в мире точек обмена трафиком между сетями."
    ],
    sights: [
        ["Рёмер", "Ратуша и фахверковые дома на площади старого города."],
        ["Музейная набережная", "Полтора десятка музеев вдоль Майна."],
        ["Main Tower", "Открытая смотровая площадка над деловым кварталом."]
    ],
    photo: "qrc:/ui/qml/MayakCity/frankfurt.jpg", photoTitle: "Frankfurt Skyline bei Nacht",
    author: "Marvin Reuter", license: "CC BY-SA 4.0", source: "Wikimedia Commons",
    licenseUrl: "https://creativecommons.org/licenses/by-sa/4.0/",
    sourceUrl: "https://commons.wikimedia.org/wiki/File:Frankfurt_Skyline_bei_Nacht.jpg"
}

var stockholm = {
    id: "stockholm", location: "Sweden/Stockholm", title: "Вы в Стокгольме, в Швеции",
    shortText: "Город на четырнадцати островах, где в Ратуше проходит Нобелевский банкет.",
    paragraphs: [
        "Стокгольм стоит на четырнадцати островах между озером Меларен и Балтийским морем, их соединяют полсотни мостов.",
        "В старом городе Гамла Стан сохранились средневековые улочки, а в Ратуше каждый год проходит Нобелевский банкет.",
        "Станции метро расписаны художниками, поэтому подземку называют самой длинной художественной галереей в мире."
    ],
    sights: [
        ["Музей «Васа»", "Военный корабль, затонувший в 1628 году и поднятый со дна в 1961-м."],
        ["Гамла Стан", "Старый город на острове: дворец, соборы и узкие улочки."],
        ["Ратуша", "Башня с тремя коронами и зал Нобелевского банкета."]
    ],
    photo: "qrc:/ui/qml/MayakCity/stockholm.jpg", photoTitle: "Stockholm by night",
    author: "Safi-iren", license: "CC BY-SA 4.0", source: "Wikimedia Commons",
    licenseUrl: "https://creativecommons.org/licenses/by-sa/4.0/",
    sourceUrl: "https://commons.wikimedia.org/wiki/File:Stockholm_by_night.jpg"
}

var cityIds = ["oslo", "helsinki", "amsterdam", "frankfurt", "stockholm"]
var cities = ({ oslo: oslo, helsinki: helsinki, amsterdam: amsterdam, frankfurt: frankfurt, stockholm: stockholm })

function cityForId(id) {
    return cityIds.indexOf(id) >= 0 ? cities[id] : null
}
