% itmo-vkr.cls
% Класс для оформления выпускной квалификационной работы ИТМО
% Требования: XeLaTeX

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{itmo-vkr}[2026/02/08 v1.0 ITMO VKR Template]

% Наследуем от article
\LoadClass[14pt,a4paper]{extarticle}

% === КОДИРОВКА И ЯЗЫК ===
\RequirePackage{fontspec}
\RequirePackage{polyglossia}
\setmainlanguage{russian}
\setotherlanguage{english}

% === ОГЛАВЛЕНИЕ (СОДЕРЖАНИЕ) ===
\RequirePackage{tocloft}

% Текст заголовка
\renewcommand{\contentsname}{\uppercase{СОДЕРЖАНИЕ}}

% Центрирование и размер заголовка "СОДЕРЖАНИЕ"
\renewcommand{\cfttoctitlefont}{\hfill\Large\bfseries}
\renewcommand{\cftaftertoctitle}{\hfill}



% === ШРИФТЫ ===
% Times New Roman для основного текста и математики
\setmainfont{Times New Roman}
\setsansfont{Times New Roman}
\setmonofont{Times New Roman}

% === ГЕОМЕТРИЯ СТРАНИЦЫ ===
\RequirePackage{geometry}
\geometry{
	a4paper,
	left=30mm,
	right=15mm,
	top=20mm,
	bottom=20mm,
	headsep=10mm,
	footskip=10mm
}

% === ИНТЕРВАЛЫ И АБЗАЦЫ ===
% Полуторный интервал
\RequirePackage{setspace}
\onehalfspacing

% Абзацный отступ 1.25 см, без интервала между абзацами
\setlength{\parindent}{1.25cm}
\setlength{\parskip}{0pt}

% === НУМЕРАЦИЯ СТРАНИЦ ===
% Номер страницы в центре нижней части
\RequirePackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\cfoot{\thepage}
\renewcommand{\headrulewidth}{0pt}
\renewcommand{\footrulewidth}{0pt}

% Нумерация страниц со сквозной нумерацией включая приложения
\setcounter{page}{1}

% === ОФОРМЛЕНИЕ ЗАГОЛОВКОВ ===
% Заголовки разделов (прописные, полужирные)
\RequirePackage{titlesec}

% Структурные элементы (СОДЕРЖАНИЕ, ВВЕДЕНИЕ, ЗАКЛЮЧЕНИЕ и т.п.)
\newcommand{\structheading}[1]{%
	\newpage
	\centerline{\textbf{\uppercase{#1}}}
	\vspace{0.5cm}
}

% Раздел (глава) - нумерованный, прописной, полужирный,
% с абзацным отступом, без центрирования
\titleformat{\section}
{\clearpage\normalfont\bfseries}
{\thesection\quad}
{0pt}
{\uppercase}

\titlespacing{\section}
{\parindent} % заголовок с абзацного отступа
{12pt plus 4pt minus 2pt}
{12pt plus 4pt minus 2pt}


% Подраздел (пункт)
\titleformat{\subsection}
{\normalfont\bfseries}
{\thesubsection\quad}
{0pt}
{}

\titlespacing{\subsection}
{\parindent}
{12pt plus 4pt minus 2pt}
{12pt plus 4pt minus 2pt}

% Подпункт
\titleformat{\subsubsection}
{\normalfont}
{\thesubsubsection\quad}
{0pt}
{}

\titlespacing{\subsubsection}
{\parindent}
{12pt plus 4pt minus 2pt}
{6pt plus 2pt minus 1pt}

% === СОДЕРЖАНИЕ ===
\RequirePackage{tocloft}

% Титр для содержания
\renewcommand{\contentsname}{\uppercase{Содержание}}

% Изменение стиля оглавления - с точками
\renewcommand{\cftsecleader}{\cftdotfill{\cftdotsep}}
\renewcommand{\cftsecaftersnum}{~}

% === ИЛЛЮСТРАЦИИ ===
\RequirePackage{graphicx}
\RequirePackage[font=normalsize,labelfont=bf]{caption}
\RequirePackage{chngcntr}

% Нумерация по разделам (убери эту строку, если нужна сквозная)
\counterwithin{figure}{section}

% Формат подписи: "Рисунок <номер> – <Название>"
\captionsetup[figure]{
	name=Рисунок,
	labelsep=endash,
	justification=centering
}


% === ТАБЛИЦЫ ===
\RequirePackage{array}
\RequirePackage{booktabs}
\RequirePackage{longtable}  % Для многостраничных таблиц
\RequirePackage{etoolbox}   % Необходим для автоматизации шапок на уровне шаблона

% ГЛОБАЛЬНЫЕ ВНУТРЕННИЕ ОТСТУПЫ В ЯЧЕЙКАХ
\setlength{\extrarowheight}{4pt} % Дополнительный отступ сверху текста
\renewcommand{\arraystretch}{1.2} % Пропорциональное увеличение высоты для отступа снизу

% Нумерация таблиц по разделам
\counterwithin{table}{section}

% Формат подписей к таблицам
\DeclareCaptionLabelFormat{table-itmo}{Таблица #2}
\captionsetup[table]{
	labelformat=table-itmo,
	labelsep=endash,
	position=above,
	justification=raggedright,
	singlelinecheck=false,
	indention=0pt,
	font={singlespacing},
	skip=6pt
}

% Автоматическое выравнивание таблиц по левому краю
\AtBeginEnvironment{table}{\raggedright}

% Настройка для longtable (многостраничные таблицы)
\RequirePackage{caption}
\captionsetup[longtable]{
	labelformat=table-itmo,
	labelsep=endash,
	justification=raggedright,
	singlelinecheck=false,
	font={singlespacing},
	skip=6pt
}

% --- АВТОМАТИЗАЦИЯ СТАНДАРТНОГО LONGTABLE НА УРОВНЕ ШАБЛОНА ---
% Этот хук автоматически захватывает первую строку longtable и:
% 1. На последующих страницах выводит надпись "Продолжение таблицы [номер]"
% 2. Повторяет эту шапку на каждой новой странице
% 3. Корректно расставляет hline без дублирования на стыках
\makeatletter
\patchcmd{\LT@array}{\tabskip\z@skip}{\tabskip\z@skip
	\gdef\LT@end@hd{%
		\endfirsthead % Завершаем отображение шапки на первой странице
		\multicolumn{\LT@cols}{r}{\textit{Продолжение таблицы \thetable}} \\ \hline
		\gdef\LT@end@hd{\endhead}% Автоматически повторяет эту же шапку на новых страницах
	}%
	\gdef\LT@end@ft{\endfoot}% Очищаем промежуточный hline со дна страниц (линии не удваиваются)
	\gdef\LT@end@last@ft{\hline\endlastfoot}% Финальная закрывающая линия ставится строго в конце таблицы
}{}{}
\makeatother




% === ФОРМУЛЫ И УРАВНЕНИЯ ===
\RequirePackage{amsmath}
\RequirePackage{amssymb}

% Нумерация формул по разделам
\renewcommand{\theequation}{\thesection.\arabic{equation}}

% Расстояние выше и ниже формулы
\setlength{\abovedisplayskip}{12pt}
\setlength{\belowdisplayskip}{12pt}

% === СПИСКИ СОКРАЩЕНИЙ И ТЕРМИНОВ ===
\RequirePackage{array}

% Сокращения: столбцом, с переносами, без рамок
\RequirePackage{array}

\usepackage{longtable}

\newenvironment{abbreviations}
{
\par\noindent
\begin{longtable}{@{}p{3cm}p{12cm}@{}}
}
{
\end{longtable}\par
}

\newcommand{\abbritem}[2]{%
#1 & #2\\
}

% Термины: таблица с рамкой
\newenvironment{termlist}{%
  \setlength{\LTpre}{0pt}%
  \setlength{\LTpost}{0pt}%
  \begin{longtable}{|>{\raggedright\arraybackslash}p{6.2cm}|>{\raggedright\arraybackslash}p{\dimexpr\linewidth-6.2cm-4\tabcolsep-3\arrayrulewidth\relax}|}
  \hline
  \endfirsthead
  \hline
  \endhead
  \endfoot
}{%
  \end{longtable}%
}

% Одна строка «термин — определение»
\newcommand{\termitem}[2]{%
  #1 & #2\\*\hline
}





% === ЛИСТИНГИ КОДА (listings + Menlo) ===
\RequirePackage{listings}
\RequirePackage{xcolor}
\RequirePackage{caption}
\RequirePackage{fontspec}
\RequirePackage{float} % для плавающих окружений на базе figure [web:6]

% базовые цвета для кода
\definecolor{codebg}{RGB}{248,248,248}
\definecolor{codeframe}{RGB}{180,180,180}
\definecolor{codecomment}{RGB}{0,128,0}
\definecolor{codekeyword}{RGB}{0,0,160}
\definecolor{codestring}{RGB}{163,21,21}

% Menlo только для кода (остальной текст остаётся Times)
\newfontfamily\itmoListingFont{Menlo}[Scale=MatchLowercase]

% переименуем тип листинга для подписи и списка
\renewcommand{\lstlistingname}{Листинг}
\renewcommand{\lstlistlistingname}{Список листингов}

% псевдоязык с русскими ключевыми словами (по желанию)
\lstdefinelanguage{RussianPseudo}{
	keywords={если,иначе,пока,для,возврат,функция},
	sensitive=true,
	comment=[l]{//},
	morecomment=[s]{/*}{*/},
	morestring=[b]"
}

% общий стиль листинга
\lstdefinestyle{itmoListing}{
	basicstyle=\itmoListingFont\small,      % Menlo
	backgroundcolor=\color{codebg},
	captionpos=b,  
	frame=single,
	framexleftmargin=14pt,                   % место под номера внутри рамки
	xleftmargin=14pt,                        % сдвиг блока
	rulecolor=\color{codeframe},
	breaklines=true,
	tabsize=4,
	showstringspaces=false,
	keywordstyle=\color{codekeyword}\bfseries,
	commentstyle=\color{codecomment},
	stringstyle=\color{codestring},
	numbers=left,                           % номера слева
	numberstyle=\tiny,
	numbersep=6pt,                          % расстояние от номера до кода
	stepnumber=1,
	firstnumber=1,
	morekeywords={если,иначе,пока,для,возврат,функция,тип,структура},
	aboveskip=10pt
}

% ГОСТ-подобная подпись: "Листинг N -- Название"
\DeclareCaptionLabelFormat{listing-itmo}{Листинг #2}
\DeclareCaptionLabelSeparator{gostsep}{\space--\space}
\captionsetup[lstlisting]{%
	labelformat=listing-itmo,
	labelsep=gostsep,
	labelfont=bf,
	textfont=normalsize,
	singlelinecheck=false,
	justification=centering,
	position=bottom,                        
	skip=5pt
}

% --- Неплавающий листинг ---
% \begin{itmolisting}[Python]{Название}
	%   код
	%   \label{lst:метка}
	% \end{itmolisting}
\lstnewenvironment{itmolisting}[3][]{%
	\lstset{
		style=itmoListing,
		language=#1,
		caption={#2},
		label={#3},       % ← метка передаётся напрямую в lstset
		resetmargins=true
	}%
}{}


% --- Плавающий листинг ---
% \begin{itmolistingfloat}[Python]{Название}{lst:label}
	%   код
	% \end{itmolistingfloat}
\newenvironment{itmolistingfloat}[3][]{%
	\begin{figure}[htbp]%
		\captionsetup{type=lstlisting}%
		\lstset{
			style=itmoListing,
			language=#1,
			caption={#2},
			label={#3},     % ← сюда, а не отдельным \label
			resetmargins=true
		}%
	}{%
	\end{figure}%
}





% === СПИСКИ И ПЕРЕЧИСЛЕНИЯ ===
\RequirePackage{enumitem}

% Настройка маркеров и отступов
\setlist[itemize]{
	label=--,
	left=\parindent,
	itemsep=0pt,
	parsep=0pt
}

\setlist[enumerate]{
	label=\arabic*),
	left=\parindent,
	itemsep=0pt,
	parsep=0pt
}

\setlist[enumerate,2]{label=\arabic{enumi}.\arabic*), left=\parindent}

% === БИБЛИОГРАФИЯ ===
\RequirePackage[backend=biber,style=gost-numeric,sorting=none]{biblatex}

% Переопределение заголовка библиографии
\defbibheading{bibliography}{%
	\newpage
	\phantomsection
	\addcontentsline{toc}{section}{СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ}%
	\centerline{\textbf{СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ}}%
	\vspace{0.5cm}%
}

% === ГИПЕРССЫЛКИ ===
\RequirePackage{hyperref}
\hypersetup{
	colorlinks=false,
	hidelinks,
	unicode=true
}

% === ВСПОМОГАТЕЛЬНЫЕ КОМАНДЫ ===

% Команда для структурных элементов без нумерации
\newcommand{\unnumberedchapter}[1]{%
	\newpage
	\phantomsection
	\addcontentsline{toc}{section}{\uppercase{#1}}
	\centerline{\textbf{\uppercase{#1}}}
	\vspace{0.5cm}
}

% Команда для вставки рисунка с правильным форматом
\newcommand{\insertfigure}[3]{
	\begin{figure}[h!]
		\centering
		\includegraphics[width=#2]{#1}
		\caption{#3}
		\label{fig:#1}
	\end{figure}
}

% Команда для обозначения приложения
\newcommand{\appendixletter}[1]{%
	\newpage
	\phantomsection
	\setcounter{figure}{0}
	\setcounter{table}{0}
	\setcounter{equation}{0}
	\renewcommand{\thefigure}{#1.\arabic{figure}}%
	\renewcommand{\thetable}{#1.\arabic{table}}%
	\renewcommand{\theequation}{#1.\arabic{equation}}%
	\centerline{\textbf{Приложение #1}}%
	\vspace{0.5cm}%
	\addcontentsline{toc}{section}{ПРИЛОЖЕНИЕ #1}%
}

\newcommand{\appendixpdf}[2]{%
	\clearpage
	\phantomsection
	\setcounter{figure}{0}%
	\setcounter{table}{0}%
	\setcounter{equation}{0}%
	\renewcommand{\thefigure}{#1.\arabic{figure}}%
	\renewcommand{\thetable}{#1.\arabic{table}}%
	\renewcommand{\theequation}{#1.\arabic{equation}}%
	\vspace{0.5cm}%
	\clearpage
	\includepdf[pages=-,scale=0.9,pagecommand={\thispagestyle{fancy}}]{#2}%
}





% === СПЕЦИАЛЬНОЕ ФОРМАТИРОВАНИЕ ===

% Выравнивание текста по умолчанию
% \RequirePackage{ragged2e}
% \RaggedRight

% Устранение переполнения строк (overfull \hbox)
\sloppy

% === ПРИЛОЖЕНИЯ ===
% Добавляем к \appendix: заголовок раздела становится двухстрочным
% «ПРИЛОЖЕНИЕ А» / «НАЗВАНИЕ», в оглавлении — «ПРИЛОЖЕНИЕ А  Название»
\apptocmd{\appendix}{%
  \pretocmd{\section}{\clearpage}{}{}%
  \titleformat{\section}[display]
    {\normalfont\bfseries\centering}
    {ПРИЛОЖЕНИЕ~\thesection}
    {4pt}
    {\uppercase}
  \titlespacing{\section}
    {0pt}{12pt plus 4pt minus 2pt}{12pt plus 4pt minus 2pt}
  \addtocontents{toc}{%
    \protect\renewcommand{\protect\cftsecpresnum}{Приложение~}%
    \protect\setlength{\protect\cftsecnumwidth}{7.5em}%
  }%
}{}{}

\endinput
