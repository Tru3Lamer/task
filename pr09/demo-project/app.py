# SPDX-FileCopyrightText: 2024 MISHARIN PAVEL
#
# SPDX-License-Identifier: MIT

import requests
from flask import Flask
import numpy as np

print("Demo app with dependencies")
print(f"Requests version: {requests.__version__}")
print(f"NumPy version: {np.__version__}")
