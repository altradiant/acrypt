from datetime import datetime

# Словарь с названиями месяцев на русском языке
months_in_russian = {
    1: "январь",
    2: "февраль",
    3: "март",
    4: "апрель",
    5: "май",
    6: "июнь",
    7: "июль",
    8: "август",
    9: "сентябрь",
    10: "октябрь",
    11: "ноябрь",
    12: "декабрь"
}

def main():

    # Получаем текущую дату
    current_date = datetime.now()

    # Получаем текущий месяц
    current_month = current_date.month

    # Возвращаем название месяца на русском языке
    current_month_in_russian = months_in_russian[current_month]

    return current_month_in_russian