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

### 3. Разработать свою систему вывода информации об объекте на любом языке, исключающий возможность инъекции SQL кода. Возможно исправление участка кода из dvwa.local
```Java
<?php

$host = '127.0.0.1'; 
$username = 'root';  
$password = '';      
$database = 'dvwa';  

$connection = new mysqli($host, $username, $password, $database);

if ($connection->connect_error) {
    die('Ошибка подключения: ' . $connection->connect_error);
}

if (isset($_GET['Submit'])) {
    $id = $_GET['id'];

    // Проверяем, что передан корректный ID (число)
    if (!ctype_digit($id)) {
        die('<pre>Ошибка: некорректный идентификатор!</pre>');
    }

    // Подготовленный запрос для предотвращения SQL-инъекций
    $stmt = $connection->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?');
    if ($stmt === false) {
        die('<pre>Ошибка подготовки запроса: ' . $connection->error . '</pre>');
    }

    $stmt->bind_param('i', $id);

    $stmt->execute();

    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo '<pre>';
            echo 'Имя: ' . htmlspecialchars($row['first_name']) . PHP_EOL;
            echo 'Фамилия: ' . htmlspecialchars($row['last_name']) . PHP_EOL;
            echo '</pre>';
        }
    } else {
        header($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found');
        echo '<pre>Ошибка: объект с ID ' . htmlspecialchars($id) . ' не найден!</pre>';
    }

    $stmt->close();
}

$connection->close();

?>
```
Данный код исключается возможность SQL-инъекций и предотвращает XSS путем использования ```htmlspecialchars```

### 4. Использовать sqlmap для нахождения уязвимости в веб-ресурсе
Для начала необходимо скачать архив с официального репозитория GitHib https://github.com/sqlmapproject/sqlmap. 
Далее установить sqlmap командой ```pip install sqlmap```
Для проверки был выбран веб-ресурс http://localhost/DVWA-master/vulnerabilities/sqli_blind/ - необходимо ввести команду ```sqlmap -u "http://localhost/DVWA-master/vulnerabilities/sqli_blind/?id=1&Submit=Submit" --cookie="PHPSESSID=lq0u1iki04o5f883grqfd8u93l; security=low" --batch --dbs```

Результат
![image](https://github.com/user-attachments/assets/3e53509b-4648-4d3d-b36c-31e6f663e76b)
![image](https://github.com/user-attachments/assets/c2c08d5e-dccb-4d82-8343-85d0bd75d97d)
![image](https://github.com/user-attachments/assets/072232c2-7c21-4206-bff6-657e998f8eea)

На основе полученных данных можно сделать следующие выводы
- Параметр ```id``` в GET-запросе идентифицирован как уязвимый к SQL-инъекциям.
- Обнаружены два типа инъекций
	- Boolean-based blind SQL Injection (слепая инъекция на основе логических выражений).
	- Time-based blind SQL Injection (слепая инъекция на основе времени).
- Доступные базы данных
	- dvwa
	- information_schema 
	- mysql 
	- performance_schema 
	- phpmyadmin
	- test

### 5. Использовать Burp для нахождения уязвимости в веб-ресурсе
![image](https://github.com/user-attachments/assets/5f92dc11-74c2-4fbc-a6ba-01b425f989e8)

![image](https://github.com/user-attachments/assets/10d037c1-5352-4c76-9955-27b5992817ba)

![image](https://github.com/user-attachments/assets/d8519558-b81b-4a98-ad18-8097e33d924e)


