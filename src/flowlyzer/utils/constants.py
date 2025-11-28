

import numpy as np

MISSING_VALUE = -100

def set_missing_value(value_type: str):

    global MISSING_VALUE
    if value_type == 'nan':
        MISSING_VALUE = np.nan
    elif value_type == '-100':
        MISSING_VALUE = -100
    else:
        MISSING_VALUE = -100

def get_missing_value():

    return MISSING_VALUE