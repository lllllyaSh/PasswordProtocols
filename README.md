# PasswordProtocols
Репозиторий для лабораторных работ по "Протоколам с парольной защитой"

Лабораторная работа 1 - Генератор хеш-значений

На языке Python был написан генератор хеш-значений для списка паролей.
На вход подается текстовый файл с паролями, кодировка, хеш-функция, количество хеш-значений в выходном файле. Остальные хеш-значения должны быть псевдослучайными.
На выходе – файл с хеш-значениями.
Список поддерживаемых хеш-функций: 
  	MD4
	MD5
	SHA-1
	SHA-256
	SHA-512
Пример запуска:

python3 protocols_lab1.py pass.txt UTF-16-LE MD4 1000 out.txt

Восстановление паролей по словарю

Пример использования:
1. Мы знаем. что пароль хешируется по определенному алгоритму и он один из самых часто используемых (в списке самых частых паролей)
2. Можно взять и ппредпосчитать хэши самых частых паролей и потом сравнить известный нам хэш с посчитанными хешами.
Написать простую утилиту для восстановления паролей по словарю. На вход подается текстовый файл – словарь – с паролями-кандидатами и текстовый файл с хешами, хеш-функцию и кодировку. На выходе: пароль + найденный в файле хеш, который ему соответствует. Распараллелить работу по ядрам с помощью multiprocessing по данным.
Пример запуска

	python3 crack_passwd.py pass.txt UTF-8 SHA1 out.txt

	qwerty123:1f341324bf12c4590c……

Тайминги нахождения паролей по известным хешам:
1. 10 хешей - 0.0763540267944336 секунд (131 кандидат/сек)
2. 100 хешей - 0.08102011680603027 секунд (1234 кандидат/сек)
3. 1000 хешей - 0.0825810432434082 секунд (12 109 кандидат/сек)
4. 10000 хешей - 0.35744714736938477 секунд (27 976 кандидат/сек)
5. 100000 хешей - 0.4939260482788086 секунд (202 470 кандидат/сек)
6. 1000000 хешей - 2.2565808296203613 секунд (443 148 кандидат/сек)

   Железо, на котором проводились замеры: Macbook PRO 2021, процессор M1 PRO
