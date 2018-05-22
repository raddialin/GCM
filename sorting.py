# -*- coding: utf-8 -*-
"""
Created on Mon Dec  4 02:38:00 2017

@author: twinz
"""

import plotly as py
import plotly.graph_objs as obj
import random

def randomSet():
    l=[]
    while (len(l)<100):
        num=random.randrange(1,101)
        if num not in l:
            l.append(num)
    return l
def insertion():
    x=list(range(101))
    y=randomSet()
    data=[obj.Bar(x=x,y=y)]
    py.offline.plot(data, filename="insertion")