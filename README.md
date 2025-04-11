# task_for_sp
## Описание  
Часть 1 - Ответом к ней является скрипт `sbom-source-generator.py` и итоговый sbom файл `source-sbom.cyclonedx.json`.  
Часть 2 - Ответом является файл `bin-sbom.cyclonedx.json`. Он был получен при помощи утилиты cdxgen. Так же приложен скрипт `try_to_analyse_binary.py` описание использования которого описано далее. Но это не является полным решением. В дополнение к этому прилагается список того что было попробовано и либо не принесло результатов, либо выдало очень мало информации.    
Было попробовано:
  1) Анализ динамически подгружаемых библиотек(Было выяснено что некоторые файлы зависят от libc.so.6, libz.so.1, libgfortran.so.1, libm.so.6)
  2) Был произведен анализ строковых констант в результате которого было выяснено, что binary3 - пакет fastjar версии 0.92, binary7 - GNU Fortran 95 (GCC), binary8 - GNU Fortran 95     runtime libraryю.
  3) Была произведена попытка декомпиляции бинарников при помощи ghidra, но из этого не получилось достать полезную информацию
  4) Были произведены попытки поиска CVE при помощи известных инструментов(например: cve-bin-tool)
  5) Были перепробованы все инструменты для работы с бинарными файлами отсюда https://cyclonedx.org/tool-center/
  6) Были найдены все потенциальные уязвимости при помощи утилиты cwe_cheker, их список для каждого бинарника указан в папке CWEs_finded  

Часть 3 - Ответом является скрипт `graph-drawer.py`	который по sbom файлу из первой части гененрирует граф зависимостей и компонентов в данном проекте.

## Использование  
Часть 1 - Для генерации сбом используется скрипт `sbom-source-generator.py`, имеет единственный обязательный аргумент   -i - путь до директории содержащей проект.  
```
python sbom-source-generator.py -i path/to/project/directory
```   
Часть 2 - `try_to_analyse_binary.py` предоставляет информацию полученную из бинарного файла, имеет обязательный аргумент  
-i - путь до ELF файла, -d - указывается для печати потенциальной документации данного пакета.
```
python try_to_analyse_binary.py -d -i path/to/project/binary
```   
Часть 3 - Для рисования графа компонентов используется скрипт `graph-drawer.py`, имеет два обязательных аргумента командной строки -i - путь до cyclonedx json файла, -o - имя файла в который будет сохранен итоговый граф(<name>.svg).
```
python graph-drawer.py -i cyclonedx.json -o graph
```
## То что не получилось 
  1) К сожалению мне так и не удалось найти рабочих инструментов для 1-ой части задания(Все что мне удалось находить требовало особенные средства сборки, например conan файлов)
  2) Была потерена версия пакета fastjar из первой части задания, т.к. она содержится в README файле, а данные файлы не имеют ни какой стандартизированной структуры поэтому получить от туда версию конкретного пакета( с учетом того что там также перечислены и другие версии пакетов нужных для работы) не представляется возможным.
  3) Похожая проблема возникла и с бинарными файлами ведь там все константные строки не стандартизированы и название пакета может быть получено только после запуска с агументом --version, но это уже не относится к статическому анализу

