#
#    Copyright 2022 - Carlos A. <https://github.com/dealfonso>
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
from datetime import datetime
import sys

__verbose = 1

def setVerbose(set = 1):
    global __verbose
    __verbose = set

def getVerbose():
    return __verbose

def s_error(x):
    msg = "[ERROR - {}] {}".format(datetime.now(), x)
    return msg

def p_error(x):
    sys.stderr.write(s_error(x) + "\n")

def r_error(x, retval = False):
    p_error(x)
    return retval

def p_debug(*args):
    global __verbose
    if __verbose > 0:
        for x in args:
            msg = "[DEBUG - {}] {}".format(datetime.now(), x)
            sys.stderr.write(msg + "\n")
