"""CI에서 분석 근거를 확보한 고정 범위. 실행하지 않고 정적 검사만 한다."""
import os


def fixed_command():
    os.system('echo fixed')


def fixed_path():
    return open('/srv/fixed/config.txt').read()


def fixed_query(cursor):
    cursor.execute('SELECT 1')
