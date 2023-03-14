# Projekt 1
*Klient pro server kalkulačku.*

Funkcionalita a známé limitace obsaženy v souboru *CHANGELOG.md*
## Překlad a spuštění

### Překlad
``` make ```

Potřeba alespoň g++ verzi 10.
### Spuštění
```
./ipkcpc -h <host> -p <port> -m <mode> 
        <host>      IPv4 adresa serveru
        <port>      'port' serveru
        <mode>      "udp" nebo "tcp"

Př.:    ipkcpc -h 1.2.3.4 -p 2023 -m udp
```

## Testování
Pro testování jsem vybral 'pairwise' kritérium pokrytí. Pro vstupní data jsem pak na základě rozhraní zvolil následující charakteristiky.
| Host          | Port                  | Mode          | STDIN         |
| -----------   | -----------           |-----------    |-----------    |
| validní       | validní               | udp           | validní       |
| nevalidní     | < 1023 nebo > 65535   | tcp           | nevalidní     |

Následně jsem použil použil [tento](https://pairwise.teremokgames.com/) nástroj na generování trojic, na základě kterých jsem vytvořil konkrétní testové vstupy.
Na testování samotné jsem si potom vytvořil shell [skript](tests/test.sh).

