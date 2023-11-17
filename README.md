# Crackme resolver. Keygen для crackme sampl'а

#### Задача - решить crackme. Необходимо найти пару ```{name, serial}``` или просто ```{serial}``` для конкретного ```name```. 

#### Для корректной работы необоходим ```angr```, ```ida```: 

##### https://github.com/angr/angr

##### https://hex-rays.com/ida-free/

#### Reverse область:

![alt text](/img/reverse.png)

#### Сэмпл crackme находится в папке ```bin```. Результаты выводятся в ```CLI```.

#### Используйте методы: ```generate_pair``` для генератора пары ```{name, serial}``` или ```generate_serial``` для генератора ```{serial}``` класса ```CrackmeResolver```.

#### Примеры результатов:
```PYTHON
[+] Success: 
        name is 'Яблоко' 
        serial is: 'Tp`nwhHapi'
[+] Success: 
        name is 'Apple' 
        serial is: '000000A70J'
[+] Success: 
        name is 'eZAKHdaiUs' 
        serial is: '0Tu0`@D`ba'
```
