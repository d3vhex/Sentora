import psutil
import time
from datetime import datetime
from modules.db import insert_record, delete_all

def get_cpu_usage():
    try:
        return psutil.cpu_percent(interval=1)
    except:
        return 0.0

def get_memory_usage():
    try:
        mem = psutil.virtual_memory()
        return {
            "total": mem.total,
            "available": mem.available,
            "used": mem.used,
            "percent": mem.percent
        }
    except:
        return {"total":0, "available":0, "used":0, "percent":0}

def main():
    psutil.cpu_percent(interval=None)
    
    while True:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cpu = psutil.cpu_percent(interval=1)
            memory = get_memory_usage()

            delete_all('resource_usage')

            record = {
                'timestamp': timestamp,
                'cpu_percent': cpu,
                'mem_total': memory['total'],
                'mem_available': memory['available'],
                'mem_used': memory['used'],
                'mem_percent': memory['percent']
            }

            insert_record('resource_usage', record)
        except Exception as e:
            print(f"[!] Resource checker error: {e}")
            
        time.sleep(2)

if __name__ == "__main__":
    main()
