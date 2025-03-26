# 1. Отримати курси евро за попередній тиждень, вивести на екран дату + курс
# 2. З отриманого словника побудувати графік зміни курсу за тиждень

import json
import requests
import matplotlib.pyplot as plt

### Part 1

# URL for request https://bank.gov.ua/NBU_Exchange/exchange_site?start=20250317&end=20250321&valcode=eur&json
response_data = requests.get("https://bank.gov.ua/NBU_Exchange/exchange_site?start=20250317&end=20250321&valcode=eur&json")

print(response_data)

response_list = json.loads(response_data.content)

for item in response_list:
    print(item['exchangedate'], item['rate'])
print()

exchange_data = []
exchange_rate = []

for item in response_list:
    exchange_data.append(item['exchangedate'])
    exchange_rate.append(item['rate'])

print(exchange_data)
print(exchange_rate)


### Part 2
# Matplotlib

plt.plot(exchange_data, exchange_rate)
plt.show()
