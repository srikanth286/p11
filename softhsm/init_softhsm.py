import subprocess

def get_the_data(data):
    lines = data.split('\n')
    arr = []
    i = 0
    for a in lines:
        if a[:4] == 'Slot':
            arr.append({})
            k = a.split(' ')[1]
            arr[i]['slot']=k
            
        if 'Serial number:' in a:
            k = a.split(':')[1]
            k = k.strip()
            arr[i]['s_num']=k
        
        if 'Initialized:' in a:
            k = a.split(':')[1]
            k = k.strip()
            arr[i]['init']=k
        
        if 'User PIN init.:' in a:
            k = a.split(':')[1]
            k = k.strip()
            arr[i]['user_pin']=k        
        
        if 'Label:' in a:
            k = a.split(':')[1]
            k = k.strip()
            arr[i]['label']=k
            i += 1
    return arr

def get_slots():
    s = subprocess.check_output([
        'softhsm2-util', 
        '--show-slots'
    ])
    arr = get_the_data(s.decode('utf-8'))
    return arr

def init_slot(slot_number, label, so_pin, pin):
    try:
        s = subprocess.check_output([
            'softhsm2-util', 
            '--init-token',
            '--slot',
            str(slot_number),
            '--label',
            label,
            '--so-pin',
            so_pin,
            '--pin',
            pin
        ])
        return True #print(s.decode('utf-8'))
    except Exception as e:
        return False

if __name__ == '__main__':
    slots = get_slots()
    if len(slots) == 1 and slots[0]['init'] == 'no':
        print('only one uninit slot')
        r = init_slot(0, 'mySlot', 'test123', 'qwerty123')
        if r:
            print(get_slots())
        else:
            print('Some error in initializing')
    else:
        print('slots initialized')
        print(slots)
