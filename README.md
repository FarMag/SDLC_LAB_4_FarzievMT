# SDLC_LAB_4_FarzievMT
**Предварительная подготовка**
Был скачан архив DVWA с официального ресурса на github.com, после чего он был установлен с использованием дистрибутивf для сборки локального веб-сервера XAMPP
![image](https://github.com/user-attachments/assets/dcc0da59-069f-46e1-827c-a9e87f4e568c)

Адрес: http://localhost/DVWA-master/login.php
![image](https://github.com/user-attachments/assets/e4547923-9971-4a80-a2f8-f612bd76712b)

# Задания
### 1. Необходимо найти участок кода, содержащий инъекцию SQL кода в задании Blind Sql Injection на сайте dvwa.local с использованием статического анализатора кода (Можно использовать официальный ресурс или виртуальную машину Web Security Dojo) 
Для анализа будет использован phpStan, который устанавливается через Composer

![image](https://github.com/user-attachments/assets/a5fcb661-eab6-4496-a6fd-5c737823406d)

С помощью команды ```vendor/bin/phpstan analyse C:\xampp\htdocs\DVWA-master\vulnerabilities\sqli_blind\index.php  --level=max``` были найдены следующие ошибки

![image](https://github.com/user-attachments/assets/ac340266-a23c-4398-b898-a4bc66fdc122)
![image](https://github.com/user-attachments/assets/675fe606-a270-4668-8243-4516429cc1c6)
![image](https://github.com/user-attachments/assets/8f581d8a-1c3c-497b-a26c-58ae755e7bbb)

Ошибки, связанные с SQL:
Ошибки на строке 64 говорят о том, что аргумент, переданный в функцию mysqli_query, имеет неопределенный тип (mixed), а должен быть объектом подключения к базе данных. Это часто встречается, если параметр SQL-запроса формируется из пользовательского ввода без проверки, что может быть связано с SQL-инъекцией.
```Java
  :64    Parameter #1 $mysql of function mysqli_error expects mysqli, object given.
         🪪  argument.type
  :64    Parameter #1 $mysql of function mysqli_query expects mysqli, mixed given.
         🪪  argument.type
```

Ошибка на строке 65 с функцией mysqli_fetch_row указывает на возможную проблему с результатом выполнения SQL-запроса. Если результат запроса ($result) является false (что бывает при ошибке SQL), это может быть связано с уязвимым запросом.
```Java
  :65    Cannot access offset 0 on array|false|null.
         🪪  offsetAccess.nonOffsetAccessible
  :65    Parameter #1 $result of function mysqli_fetch_row expects mysqli_result, mysqli_result|true given.
         🪪  argument.type
```

### 2. Проанализировать код и сделать кодревью, указав слабые места
```Java
<?php

\
if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = $_GET[ 'id' ];

\
	// Check database
	$getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

\
	// Get results
	$num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
	if( $num > 0 ) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	}
	else {
		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

\
		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}

\
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

\
?>
```

Анализ код с помощью phpStan
![image](https://github.com/user-attachments/assets/08e61d5b-72cb-4702-a245-37b0d0d53e87)

Кодревью:
1. SQL-инъекция. Пользовательский ввод ```($_GET['id'])``` напрямую передается в SQL-запрос, что делает код уязвимым для SQL-инъекций.
```Java
$getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid );
```


2. Необработанные ошибки базы данных
```Java
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors
```


3. Потенциальная ошибка с ```mysqli_num_rows```. Функция ```mysqli_num_rows``` может вызвать ошибку, если ```$result``` — это невалидный объект
```Java
$num = @mysqli_num_rows($result);
```


4. Неинициализированная переменная ```$html```
```Java
$html .= '<pre>User ID exists in the database.</pre>';
```


5. Проблема с закрытием соединения. Закрытие соединения с базой данных реализовано неэффективно. К тому же, передаваемый объект может быть невалидным, что приведет к ошибке.
```Java
((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
```


6. Использование HTTP-заголовков. После указания статуса 404 важно также завершить выполнение скрипта командой ```exit```.
```Java
header($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found');
```

### 3. Разработать свою систему вывода информации об объекте на любом языке, исключающий взможность инъекции SQL кода. Возможно исправление участка кода из dvwa.local


### 4. Использовать sqlmap для нахождения уязвимости в веб-ресурсе

   
### 5. Использовать Burp для нахождения уязвимости в веб-ресурсе
