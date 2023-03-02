'''unique json

@author : jumormt
@version : 1.0
'''
__author__ = "jumormt"

import json
import hashlib
import os
import jsonlines


def getMD5(s):
    '''
    得到字符串s的md5加密后的值

    :param s:
    :return:
    '''
    hl = hashlib.md5()
    hl.update(s.encode("utf-8"))
    return hl.hexdigest()


def uniqueDir(xfg_list):
    """
    @description  : merge xfg in jsonline format to json format, then symbolize , tokenize de-duplication
    ---------
    @param  :xfg_path: the dir of xfg in jsonline format
    -------
    @Returns  :
    -------
    """
    
    md5Dict = dict()
    
   
    #here cfg is xfg
    for cfg in xfg_list:# for one cfg
        nodes_line_sym = cfg['nodes-line-sym']
        target = cfg['target']
        nodes_line_md5 = list()
        for nls in nodes_line_sym:
            nodes_line_md5.append(getMD5(nls))# md5 each line
        edges_No = cfg['edges-No']
        edges_No_md5 = list()
        for edges in edges_No:
            edges_No_md5.append([nodes_line_md5[edges[0]], nodes_line_md5[edges[1]]])
        edges_No_md5 = sorted(edges_No_md5)
        cfgMD5 = getMD5(str(edges_No_md5))# md5 all edges - cfg

        if cfgMD5 not in md5Dict.keys():
            md5Dict[cfgMD5] = dict()
            md5Dict[cfgMD5]["target"] = target
            md5Dict[cfgMD5]["cfg"] = cfg
        else:# conflict - mark as -1
            md5Target = md5Dict[cfgMD5]["target"]
            if (md5Target != -1 and md5Target != target):
                md5Dict[cfgMD5]["target"] = -1
   
            

    return md5Dict


def writeBigJson(md5Dict):
    '''

    :param OUTDIR:
    :param md5Dict:
    :return:
    '''
    
    newJsonFileContent = list()

    for mdd5 in md5Dict:
        if (md5Dict[mdd5]["target"] != -1):# dont write conflict sample
            newJsonFileContent.append(md5Dict[mdd5]["cfg"])

    return newJsonFileContent



def main(args):
    CWEID = args.CWEID
    DIR = "/home/cry/chengxiao/dataset/svf-related/CWE{}/xfg-sym/".format(CWEID)
    md5Dict = uniqueDir(DIR)

    OUTDIR = "/home/cry/chengxiao/dataset/svf-related/CWE{}/xfg-sym-unique/".format(CWEID)
    if(not os.path.exists(OUTDIR)):
        os.mkdir(OUTDIR)

    xfgNum = writeBigJson(OUTDIR, md5Dict)

    print("end unique - total {} xfgs!".format(xfgNum))


if __name__ == '__main__':
    
   pass
