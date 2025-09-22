"""
Constants and global settings for DLL Flowlyzer.
"""

import numpy as np

# Default missing data value - can be changed by configuration
MISSING_VALUE = -100

def set_missing_value(value_type: str):
    """Set the global missing value based on configuration."""
    global MISSING_VALUE
    if value_type == 'nan':
        MISSING_VALUE = np.nan
    elif value_type == '-100':
        MISSING_VALUE = -100
    else:
        MISSING_VALUE = -100

def get_missing_value():
    """Get the current missing value setting."""
    return MISSING_VALUE