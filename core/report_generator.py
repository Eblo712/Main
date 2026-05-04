"""Генератор HTML-отчётов с детерминированной группировкой модулей и описаниями."""
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from jinja2 import Environment, BaseLoader, select_autoescape
from urllib.parse import quote
from core.module_classifier import classify_module, get_module_category_and_description

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчёт: {{ file_name }}</title>
    <style>
        :root {
            --bg: #f5f5f5;
            --card-bg: white;
            --text: #303030;
            --accent: #007aff;
            --border: #d1d1d1;
            --hover: #f0f0f5;
        }
        body {
            font-family: "Segoe UI", system-ui, sans-serif;
            font-size: 12px;
            margin: 20px;
            background: var(--bg);
            color: var(--text);
        }
        h1, h2 { color: var(--accent); font-size: 14px; }
        .back-link {
            display: block;
            margin-bottom: 20px;
            color: var(--accent);
            text-decoration: none;
        }
        .back-link:hover { text-decoration: underline; }
        .search { margin-bottom: 15px; }
        .search input {
            width: 100%; padding: 10px; border: 1px solid var(--border);
            border-radius: 6px; font-size: 12px;
        }
        .card {
            background: var(--card-bg); border-radius: 10px;
            margin: 12px 0; padding: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .card-header {
            cursor: pointer; font-weight: 600;
            display: flex; justify-content: space-between; align-items: center;
            font-size: 12px;
        }
        .card-body { display: none; margin-top: 8px; }
        .card.open .card-body { display: block; }
        table {
            width: 100%; border-collapse: collapse; margin: 8px 0;
            font-size: 11px;
        }
        th, td {
            text-align: left; padding: 6px; border-bottom: 1px solid var(--border);
        }
        th { background: var(--hover); }
        .code-block {
            font-family: "Consolas", "Courier New", monospace;
            white-space: pre-wrap;
            background: #f0f0f5;
            padding: 10px;
            border-radius: 6px;
            font-size: 11px;
            line-height: 1.4;
            overflow-x: auto;
        }
        .badge {
            display: inline-block; background: var(--accent); color: white;
            border-radius: 10px; padding: 2px 8px; font-size: 10px; margin-left: 8px;
        }
        .module-list {
            columns: 2;
            -webkit-columns: 2;
            -moz-columns: 2;
            list-style: none;
            padding-left: 0;
        }
        .module-list li {
            padding: 2px 0;
            font-family: monospace;
        }
        .unknown-section {
            margin-top: 16px;
            border-left: 4px solid #ff9500;
            padding-left: 16px;
        }
        .section-list {
            columns: 2;
            -webkit-columns: 2;
            -moz-columns: 2;
            list-style: none;
            padding-left: 0;
        }
        .section-list li {
            padding: 2px 0;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <a class="back-link" href="{{ back_link }}">← Назад к сводному отчёту</a>

    <h1>Отчёт анализа: {{ file_name }}</h1>

    <div class="search">
        <input type="text" id="quickSearch" placeholder="Поиск по функциям, импортам, экспортам...">
    </div>

{% if is_elf %}
    <h2>Необходимые библиотеки (.so) <span class="badge">{{ needed_libs|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Список библиотек</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if needed_libs %}
            <ul class="module-list searchable">
                {% for lib in needed_libs %}
                <li>{{ lib }}</li>
                {% endfor %}
            </ul>
            {% else %}<p>Не найдено необходимых библиотек.</p>{% endif %}
        </div>
    </div>

    <h2>Импортируемые функции <span class="badge">{{ imports|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Таблица импортов</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if imports %}
            <table>
                <tr><th>Имя</th><th>Адрес</th><th>Библиотека</th></tr>
                {% for imp in imports %}
                <tr class="searchable">
                    <td>{{ imp.name }}</td><td>{{ imp.address }}</td><td>{{ imp.module }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}<p>Нет импортируемых функций.</p>{% endif %}
        </div>
    </div>
{% else %}
    <!-- PE-режим: группировка по модулям -->
    <h2>Импортированные модули (опознанные) <span class="badge">{{ known_modules|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Список модулей</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if known_modules %}
            <ul class="module-list searchable">
                {% for mod in known_modules %}
                <li>{{ mod }}</li>
                {% endfor %}
            </ul>
            {% else %}<p>Нет опознанных модулей.</p>{% endif %}
        </div>
    </div>

    {% if unknown_modules %}
    <div class="unknown-section">
        <h2>Импортированные модули (неопознанные) <span class="badge">{{ unknown_modules|length }}</span></h2>
        <div class="card">
            <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
                <span>Требуют ручного анализа</span><span>▾</span>
            </div>
            <div class="card-body">
                <ul class="module-list searchable">
                    {% for mod in unknown_modules %}
                    <li>{{ mod }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </div>
    {% endif %}

    <h2>Импортируемые функции <span class="badge">{{ imports|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Таблица импортов</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if imports %}
            <table>
                <tr><th>Имя</th><th>Модуль</th></tr>
                {% for imp in imports %}
                <tr class="searchable">
                    <td>{{ imp.name }}</td><td>{{ imp.module }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}<p>Нет импортируемых функций.</p>{% endif %}
        </div>
    </div>
{% endif %}

    <h2>Экспортируемые функции <span class="badge">{{ exports|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Таблица экспорта</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if exports %}
            <table>
                <tr><th>Имя</th><th>Адрес</th><th>Ординал</th></tr>
                {% for exp in exports %}
                <tr class="searchable">
                    <td>{{ exp.name }}</td><td>{{ exp.address }}</td><td>{{ exp.ordinal }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}<p>Нет экспортируемых функций.</p>{% endif %}
        </div>
    </div>

    {% if elf_sections %}
    <h2>Секции ELF <span class="badge">{{ elf_sections|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Обнаруженные секции</span><span>▾</span>
        </div>
        <div class="card-body">
            <ul class="section-list searchable">
                {% for sec in elf_sections %}
                <li>{{ sec }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>
    {% endif %}

    <h2>Дизассемблированные функции <span class="badge">{{ functions|length }}</span></h2>
    {% for func in functions %}
    <div class="card">
        <div class="card-header searchable" onclick="this.parentElement.classList.toggle('open')">
            <span>{{ func.name }} <small>({{ func.start_ea }}, размер: {{ func.size }} байт)</small></span>
            <span>▾</span>
        </div>
        <div class="card-body">
            <strong>Hex-дамп:</strong>
            <div class="code-block">{{ func.hexdump }}</div>

            <strong>Дизассемблирование:</strong>
            <div class="code-block">{{ func.instructions_text }}</div>

            {% if func.pseudocode %}
            <strong>Псевдокод:</strong>
            <div class="code-block">{{ func.pseudocode }}</div>
            {% endif %}
        </div>
    </div>
    {% endfor %}

    <script>
        const searchInput = document.getElementById('quickSearch');
        searchInput.addEventListener('input', function() {
            const term = this.value.toLowerCase();
            document.querySelectorAll('.searchable').forEach(el => {
                el.style.display = el.textContent.toLowerCase().includes(term) ? '' : 'none';
            });
        });
        document.querySelectorAll('.card').forEach((card, index) => {
            if (index === 0) card.classList.add('open');
        });
    </script>
</body>
</html>"""

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Сводный отчёт анализа</title>
    <style>
        :root {
            --bg: #f5f5f5;
            --card-bg: white;
            --text: #303030;
            --accent: #007aff;
            --border: #d1d1d1;
            --hover: #f0f0f5;
        }
        body {
            font-family: "Segoe UI", system-ui, sans-serif;
            font-size: 12px;
            margin: 20px;
            background: var(--bg);
            color: var(--text);
        }
        h1, h2 { color: var(--accent); font-size: 14px; }
        h3 {
            font-size: 13px;
            margin: 10px 0 4px;
            color: #555;
        }
        .card {
            background: var(--card-bg); border-radius: 10px;
            margin: 12px 0; padding: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        ul { padding-left: 20px; }
        li { margin: 4px 0; }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .badge {
            display: inline-block; background: var(--accent); color: white;
            border-radius: 10px; padding: 2px 8px; font-size: 10px; margin-left: 8px;
        }
        .file-tree {
            font-family: monospace;
            margin: 0;
            padding-left: 0;
            list-style: none;
        }
        .file-tree li {
            padding: 2px 0;
        }
        .category-description {
            font-size: 11px;
            color: #666;
            margin: 0 0 8px 20px;
            font-style: italic;
        }
        .module-description {
            font-size: 11px;
            color: #666;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <h1>Сводный отчёт анализа</h1>

    <div class="card">
        <h2>Общая информация</h2>
        <p><strong>Директория анализа:</strong> {{ input_dir }}</p>
        <p><strong>Исследовано модулей:</strong> {{ total_modules }}</p>
        {% if ida_info %}
        <h3>Характеристики IDA Pro</h3>
        <ul>
            <li><strong>Версия ядра:</strong> {{ ida_info.kernel_version }}</li>
        </ul>
        {% endif %}
    </div>

    <div class="card">
        <h2>Классификация импортированных модулей</h2>
        {% if grouped_categories %}
            {% for category in grouped_categories %}
                <h3>{{ category.name }} <span class="badge">{{ category.count }}</span></h3>
                {% if category.description %}
                <p class="category-description">{{ category.description }}</p>
                {% endif %}
                <ul>
                    {% for mod in category.modules %}
                        <li><strong>{{ mod.name }}</strong><span class="module-description">: {{ mod.desc }}</span></li>
                    {% endfor %}
                </ul>
            {% endfor %}
        {% else %}
        <p>Модули не найдены.</p>
        {% endif %}
    </div>

    {% if elf_sections %}
    <div class="card">
        <h2>Обнаруженные секции ELF</h2>
        <ul>
            {% for sec in elf_sections %}
            <li>{{ sec }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="card">
        <h2>Исследованные файлы</h2>
        {% if reports %}
        <ul class="file-tree">
            {% for report in reports %}
            <li>📄 <a href="{{ report.filename }}" target="_blank">{{ report.display_name }}</a></li>
            {% endfor %}
        </ul>
        {% else %}
        <p>Файлы не найдены.</p>
        {% endif %}
    </div>
</body>
</html>"""


class ReportGenerator:
    """Создаёт HTML-отчёты из JSON-файлов экспорта."""

    def __init__(self):
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.template = self.env.from_string(REPORT_TEMPLATE)
        self.index_template = self.env.from_string(INDEX_TEMPLATE)

    def _compute_back_link(self, report_rel_path: Path) -> str:
        """Вычисляет относительный путь к index.html из отчёта."""
        depth = len(report_rel_path.parent.parts)
        return ("../" * depth) + "index.html"

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None,
                           reports_dir: Optional[Path] = None) -> Path:
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        is_elf = data.get("is_elf", False)

        # Для PE формируем списки опознанных/неопознанных модулей как раньше
        if not is_elf:
            known = []
            unknown = []
            elf = []
            seen = set()
            for imp in data.get("imports", []):
                mod = imp.get("module")
                if not mod or mod.lower() == "unknown":
                    continue
                if mod in seen:
                    continue
                seen.add(mod)
                if mod.startswith("."):
                    elf.append(mod)
                    continue
                category = classify_module(mod)
                if "Неопознанный" in category:
                    unknown.append(mod)
                else:
                    known.append(mod)

            data["known_modules"] = sorted(known)
            data["unknown_modules"] = sorted(unknown)
            if "elf_sections" not in data:
                data["elf_sections"] = sorted(elf)

        if "elf_sections" not in data:
            data["elf_sections"] = []

        if "exports" not in data:
            data["exports"] = []

        if output_html is None:
            output_html = json_path.with_suffix('.html')
        output_html.parent.mkdir(parents=True, exist_ok=True)

        # Вычисляем ссылку на индекс
        if reports_dir is not None:
            try:
                rel = output_html.relative_to(reports_dir)
                back_link = self._compute_back_link(rel)
            except ValueError:
                back_link = "index.html"
        else:
            back_link = "index.html"
        data["back_link"] = back_link

        html = self.template.render(data)
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html)

        return output_html

    def generate_index(self, reports_dir: Path, input_dir: Path,
                       reports: List[dict], unique_modules: List[str],
                       ida_info: Optional[Dict[str, Any]] = None,
                       elf_sections: Optional[List[str]] = None) -> Path:
        """
        Создаёт индексный файл index.html в reports_dir.
        :param reports: список словарей {'filename': относительный_путь, 'display_name': текст}
        :param unique_modules: список имён модулей (НЕ секций) – для ELF это имена .so библиотек
        :param elf_sections: список обнаруженных секций ELF
        """
        # Кодируем пробелы в ссылках
        for report in reports:
            report["filename"] = quote(report["filename"])

        categories = {}
        for mod in unique_modules:
            cat, desc = get_module_category_and_description(mod)
            categories.setdefault(cat, {"description": desc, "modules": []})
            categories[cat]["modules"].append({
                "name": mod,
                "desc": classify_module(mod)
            })

        grouped_list = []
        sorted_cats = sorted([c for c in categories if c != "Неопознанные модули"])
        if "Неопознанные модули" in categories:
            sorted_cats.append("Неопознанные модули")

        for cat in sorted_cats:
            info = categories[cat]
            info["modules"] = sorted(info["modules"], key=lambda x: x["name"].lower())
            grouped_list.append({
                "name": cat,
                "description": info["description"],
                "modules": info["modules"],
                "count": len(info["modules"]),
            })

        data = {
            "input_dir": str(input_dir),
            "total_modules": len(reports),
            "grouped_categories": grouped_list,
            "reports": reports,
            "ida_info": ida_info,
            "elf_sections": sorted(elf_sections or []),
        }

        index_path = reports_dir / "index.html"
        html = self.index_template.render(data)
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Сводный отчёт сохранён: {index_path}")
        return index_path