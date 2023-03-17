# Funkcionalita a známé limitace
## Funkcionalita
Kromě funcionality požadované zadaním, je v projektu implementováno získání IPv4 adresy pomocí jména využitím funkce gethostbyname.

## Limitace
### Bufery
Velikosti bufferů se liší podle módu a jsou následující.
| tcp   | udp   |
| ----- | ----- |
| 1024  | 256   |

Velikost udp bufferu je dána 'IPK Calculator Protocol', který říká, že 2. byte, který server v rámci udp komunikace obdrží, bude velikost následující zprávy. Rozsah bytu je <0 , 255>, z toho poslední znak je rezervován pro ukončovací znak '\0'.

Velikost u tcp byla stanovena arbitrárně. Poslední znak je stejně jako u udp rezervován.

Input, který se nevejde do bufferu, bude bez jakéhokoli upozornění od programu odignorován.
