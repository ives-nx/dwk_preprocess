import csv
import os
from slicing import get_data
import sys
sys.path.append("..")
import xml.etree.ElementTree as ET
import json

def getFlist(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if file.endswith('.c') or file.endswith('.cpp'):
                file_list.append(os.path.join(root, file))
                
    return file_list


def joern_parse(data_path):
    """
    @description  : use joern to parse c/cpp
    ---------
    @param  : data_path: c/cpp dir
    -------
    @Returns  : xfg_list
    -------
    """
    
    xfg_list = []
    workspace = 'joern'
    os.chdir(workspace)
    cmd = './joern-parse output/ '+data_path
    print('CMD: '+cmd)
    os.system(cmd)
    current_path = os.path.abspath(data_path)
    print(current_path)
    c_files = getFlist(current_path)
    csv_dir = './output'
    for c_file in c_files:
        csv_path = csv_dir + c_file
        xfgs = get_data(csv_path, c_file)
        xfg_list.extend(xfgs)
    return xfg_list


if __name__ == "__main__":
    root_dir = "/home/niexu/project/python/preprocess/test"
    xfg_list = joern_parse(root_dir)
    print(xfg_list)
    with open('test.json', 'w') as f:
        json.dump(xfg_list, f, indent=2)
    # print(os.path.basename("/home/niexu/project/python/preprocess/test.cpp"))
    