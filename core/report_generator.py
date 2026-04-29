"""Генератор HTML-отчётов с классификацией модулей (описания только в индексе)."""
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from jinja2 import Environment, BaseLoader, select_autoescape
from core.module_classifier import classify_module

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
        .hexdump {
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
    </style>
</head>
<body>
    <a class="back-link" href="index.html">← Назад к сводному отчёту</a>

    <h1>Отчёт анализа: {{ file_name }}</h1>

    <div class="search">
        <input type="text" id="quickSearch" placeholder="Поиск по функциям, импортам, экспортам...">
    </div>

    <!-- Импортированные модули (только имена, без описаний) -->
    <h2>Импортированные модули <span class="badge">{{ modules|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Список модулей</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if modules %}
            <ul class="module-list searchable">
                {% for mod in modules %}
                <li>{{ mod }}</li>
                {% endfor %}
            </ul>
            {% else %}<p>Нет импортированных модулей.</p>{% endif %}
        </div>
    </div>

    <!-- Импорты -->
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

    <!-- Экспорты -->
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

    <!-- Функции -->
    <h2>Дизассемблированные функции <span class="badge">{{ functions|length }}</span></h2>
    {% for func in functions %}
    <div class="card">
        <div class="card-header searchable" onclick="this.parentElement.classList.toggle('open')">
            <span>{{ func.name }} <small>({{ func.start_ea }}, размер: {{ func.size }} байт)</small></span>
            <span>▾</span>
        </div>
        <div class="card-body">
            <strong>Hex-дамп:</strong>
            <div class="hexdump">{{ func.hexdump }}</div>

            <strong>Дизассемблирование:</strong>
            <table>
                <tr><th>Адрес</th><th>Инструкция</th></tr>
                {% for insn in func.instructions %}
                <tr class="searchable">
                    <td>{{ insn.address }}</td>
                    <td>{{ insn.instruction }}</td>
                </tr>
                {% endfor %}
            </table>
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
        .file-tree {
            font-family: monospace;
            margin: 0;
            padding-left: 0;
            list-style: none;
        }
        .file-tree li {
            padding: 2px 0;
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
        {% if classified_modules %}
        <ul>
            {% for mod_info in classified_modules %}
            <li><strong>{{ mod_info.module }}</strong>: {{ mod_info.category }}</li>
            {% endfor %}
        </ul>
        {% else %}
        <p>Модули не найдены.</p>
        {% endif %}
    </div>

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

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None) -> Path:
        """Генерирует HTML из JSON-файла экспорта (модули без описаний)."""
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Собираем только уникальные имена модулей
        modules_set = set()
        for imp in data.get("imports", []):
            mod = imp.get("module")
            if mod and mod.lower() != "unknown":
                modules_set.add(mod)
        data["modules"] = sorted(modules_set)   # простой список строк

        if "exports" not in data:
            data["exports"] = []

        if output_html is None:
            output_html = json_path.with_suffix('.html')
        output_html.parent.mkdir(parents=True, exist_ok=True)

        html = self.template.render(data)
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html)

        return output_html

    def generate_index(self, reports_dir: Path, input_dir: Path,
                       report_files: List[Path], unique_modules: List[str],
                       ida_info: Optional[Dict[str, Any]] = None) -> Path:
        """
        Создаёт index.html с полной классификацией модулей.
        """
        reports = []
        for path in report_files:
            display_name = path.stem
            reports.append({
                "filename": path.name,
                "display_name": display_name,
            })

        # Классифицируем каждый уникальный модуль
        classified = [
            {"module": mod, "category": classify_module(mod)}
            for mod in unique_modules
        ]

        data = {
            "input_dir": str(input_dir),
            "total_modules": len(report_files),
            "unique_modules": unique_modules,
            "classified_modules": classified,
            "reports": reports,
            "ida_info": ida_info,
        }

        index_path = reports_dir / "index.html"
        html = self.index_template.render(data)
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Сводный отчёт сохранён: {index_path}")
        return index_path