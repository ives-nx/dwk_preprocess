#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
from os.path import join, isdir
import csv
from real_world_symbolic import clean_gadget,  tokenize_gadget_tolist
from uniqueJson import writeBigJson, uniqueDir
import jsonlines
def extract_line_number(idx, nodes):
    while idx >= 0:
        c_node = nodes[idx]
        if 'location' in c_node.keys():
            location = c_node['location']
            if location.strip() != '':
                try:
                    ln = int(location.split(':')[0])
                    return ln
                except:
                    pass
        idx -= 1
    return -1


def read_csv(csv_file_path):
    data = []
    with open(csv_file_path) as fp:
        header = fp.readline()
        header = header.strip()
        h_parts = [hp.strip() for hp in header.split('\t')]
        for line in fp:
            line = line.strip()
            instance = {}
            lparts = line.split('\t')
            for i, hp in enumerate(h_parts):
                if i < len(lparts):
                    content = lparts[i].strip()
                else:
                    content = ''
                instance[hp] = content
            data.append(instance)
        return data


def extract_nodes_with_location_info(nodes):
    # Will return an array identifying the indices of those nodes in nodes array,
    # another array identifying the node_id of those nodes
    # another array indicating the line numbers
    # all 3 return arrays should have same length indicating 1-to-1 matching.
    node_indices = []
    node_ids = []
    line_numbers = []
    node_id_to_line_number = {}
    for node_index, node in enumerate(nodes):
        assert isinstance(node, dict)
        if 'location' in node.keys():
            location = node['location']
            if location == '':
                continue
            line_num = int(location.split(':')[0])
            node_id = node['key'].strip()
            node_indices.append(node_index)
            node_ids.append(node_id)
            line_numbers.append(line_num)
            node_id_to_line_number[node_id] = line_num
    return node_indices, node_ids, line_numbers, node_id_to_line_number


def create_adjacency_list(line_numbers,
                          node_id_to_line_numbers,
                          edges,
                          data_dependency_only=False):
    adjacency_list = {}
    for ln in set(line_numbers):
        adjacency_list[ln] = [set(), set()]
    for edge in edges:
        edge_type = edge['type'].strip()
        if True:  #edge_type in ['IS_AST_PARENT', 'FLOWS_TO']:
            start_node_id = edge['start'].strip()
            end_node_id = edge['end'].strip()
            if start_node_id not in node_id_to_line_numbers.keys(
            ) or end_node_id not in node_id_to_line_numbers.keys():
                continue
            start_ln = node_id_to_line_numbers[start_node_id]
            end_ln = node_id_to_line_numbers[end_node_id]
            if not data_dependency_only:
                if edge_type == 'CONTROLS':  #Control Flow edges
                    adjacency_list[start_ln][0].add(end_ln)
            if edge_type == 'REACHES':  # Data Flow edges
                adjacency_list[start_ln][1].add(end_ln)
    return adjacency_list


def create_forward_slice(adjacency_list, line_no):
    sliced_lines = set()
    sliced_lines.add(line_no)
    stack = list()
    stack.append(line_no)
    while len(stack) != 0:
        cur = stack.pop()
        if cur not in sliced_lines:
            sliced_lines.add(cur)
        adjacents = adjacency_list[cur]
        for node in adjacents:
            if node not in sliced_lines:
                stack.append(node)
    sliced_lines = sorted(sliced_lines)
    return sliced_lines


def combine_control_and_data_adjacents(adjacency_list):
    cgraph = {}
    data_graph = {}
    for ln in adjacency_list:
        cgraph[ln] = set()
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][0])
        cgraph[ln] = cgraph[ln].union(adjacency_list[ln][1])

        data_graph[ln] = set()
        data_graph[ln] = data_graph[ln].union(adjacency_list[ln][1])
    return cgraph, data_graph


def invert_graph(adjacency_list):
    igraph = {}
    for ln in adjacency_list.keys():
        igraph[ln] = set()
    for ln in adjacency_list:
        adj = adjacency_list[ln]
        for node in adj:
            igraph[node].add(ln)
    return igraph
    pass


def create_backward_slice(adjacency_list, line_no):
    inverted_adjacency_list = invert_graph(adjacency_list)
    return create_forward_slice(inverted_adjacency_list, line_no)

def combined_graph_to_dict(combined_graph, file_path):
    file_contents = list()   
    with open( file_path,
                "r",
                encoding="utf-8",
                errors="ignore") as f:
        file_contents=f.readlines()
    pdg = dict()
    nodes = []
    edges = []
    line_to_id_dict = {}
    for index, ln in enumerate(combined_graph, start=0) :
        node_info = dict()
        node_info['id'] = index
        node_info['line'] = ln
        node_info['label'] = file_contents[int(ln)-1]
        nodes.append(node_info)
        line_to_id_dict[ln] = index
    e_index = 0
    for ln_start in combined_graph:
        for ln_end in combined_graph[ln_start]:
            start = line_to_id_dict[ln_start]
            end = line_to_id_dict[ln_end]
            edge_info = dict()
            edge_info['id'] = e_index
            edge_info['source'] = start
            edge_info['target'] = end
            edges.append(edge_info)
    pdg['file'] = file_path
    pdg['nodes'] = nodes
    pdg['edges'] = edges
    return pdg

def get_all_xfg_node_forward(node_id, node_id_to_line, edges, xfg_nodes_list, visted):
    visted.add(node_id)
    if node_id_to_line[str(node_id)] != 0 and node_id not in xfg_nodes_list:
        xfg_nodes_list.append(node_id)
    for edge in edges:
        if edge['source'] == node_id and edge['target'] not in visted:
            get_all_xfg_node_forward(edge['target'], node_id_to_line, edges, xfg_nodes_list, visted)

def get_all_xfg_node_backward(node_id, node_id_to_line, edges, xfg_nodes_list, visted):
    visted.add(node_id)
    if node_id_to_line[str(node_id)] != 0 and node_id not in xfg_nodes_list:
        xfg_nodes_list.append(node_id)
    for edge in edges:
        if edge['target'] == node_id and edge['source'] not in visted:
            get_all_xfg_node_backward(edge['source'], node_id_to_line, edges, xfg_nodes_list, visted)

def xfg_generator(pdg_json, line):
    # pdg_json = dict()
    # with open(file_name+'-PDG.json', 'r', encoding = 'utf-8') as f:
    #     pdg_json = json.load(f)
    #     f.close()

    node_line_to_id = dict()
    node_id_to_line = dict()

    nodes = pdg_json['nodes']
    edges = pdg_json['edges']

    for node in nodes:
        node_id_to_line[str(node['id'])] = str(node['line'])
        node_line_to_id[str(node['line'])] = str(node['id'])
    sensi_id = None
    if str(line) in node_line_to_id.keys():
        sensi_id = int(node_line_to_id[str(line)])
    if sensi_id == None:
        return None
    xfg_nodes_list = list()
    froward_visted = set()
    backward_visted = set()
    get_all_xfg_node_forward(sensi_id, node_id_to_line, edges, xfg_nodes_list, froward_visted)
    get_all_xfg_node_backward(sensi_id, node_id_to_line, edges, xfg_nodes_list, backward_visted)

    print(xfg_nodes_list)

    xfg = dict()
    xfg_nodes = list()
    xfg_edges = list()
    idx = 0
    xfg_node_line_to_id = dict()
    for node in nodes:
        if node['id'] in xfg_nodes_list:
            new_node = dict()
            new_node['id'] = idx
            new_node['line'] = node['line']
            new_node['label'] = node['label'].replace('\t', '')
            xfg_node_line_to_id[str(node['line'])] = idx
            idx = idx + 1
            xfg_nodes.append(new_node)
    xfg_edges_list = list()
    for edge in edges:
        source = edge['source']
        target = edge['target']
        if source in xfg_nodes_list and target in xfg_nodes_list:
            xfg_edges_list.append(node_id_to_line[str(source)]+"_"+node_id_to_line[str(target)])
    
    for idx, edge in enumerate(xfg_edges_list, start=0): 
        lines = edge.split("_")
        source = lines[0]
        target = lines[1]
        new_edge = dict()
        new_edge['id'] = idx
        new_edge['source'] = xfg_node_line_to_id[source]
        new_edge['target'] = xfg_node_line_to_id[target]
        xfg_edges.append(new_edge)
    
    xfg['file'] = pdg_json['file']
    xfg['sensi_line'] = line
    xfg['nodes'] = xfg_nodes
    xfg['edges'] = xfg_edges

    
    # with open(file_name+'-XFG.json', 'w', encoding = 'utf-8') as f:
    #     json.dump(xfg, f, indent = 2)
    #     f.close()
    return xfg

def get_data(csv_root, source_root):
    
    sensi_api_path = "../resources/sensiAPI.txt"
    
    # cpg_list = [join(root, fl) for fl in os.listdir(root) if isdir(join(root, fl))]
    cpg_list= [csv_root]
    src_list = [source_root]
    

    with open(sensi_api_path, "r", encoding="utf-8") as f:
        sensi_api_set = set([api.strip() for api in f.read().split(",")])
       

    all_data = list()
    for cpg,src in zip(cpg_list, src_list):
        nodes_path = join(cpg, "nodes.csv")
        edges_path = join(cpg, "edges.csv")
        with open(nodes_path, "r") as f:
            nodes = [node for node in csv.DictReader(f, delimiter='\t')]
        call_lines = set()
        array_lines = set()
        ptr_lines = set()
        arithmatic_lines = set()
        if len(nodes) == 0:
            continue
        for node_idx, node in enumerate(nodes):
            ntype = node['type'].strip()
            if ntype == 'CallExpression':
                function_name = nodes[node_idx + 1]['code']
                if function_name is None or function_name.strip() == '':
                    continue
                if function_name.strip() in sensi_api_set:
                    line_no = extract_line_number(node_idx, nodes)
                    if line_no > 0:
                        call_lines.add(line_no)
            elif ntype == 'ArrayIndexing':
                line_no = extract_line_number(node_idx, nodes)
                if line_no > 0:
                    array_lines.add(line_no)
            elif ntype == 'PtrMemberAccess':
                line_no = extract_line_number(node_idx, nodes)
                if line_no > 0:
                    ptr_lines.add(line_no)
            elif node['operator'].strip() in ['+', '-', '*', '/']:
                line_no = extract_line_number(node_idx, nodes)
                if line_no > 0:
                    arithmatic_lines.add(line_no)


        nodes = read_csv(nodes_path)
        edges = read_csv(edges_path)
        node_indices, node_ids, line_numbers, node_id_to_ln = extract_nodes_with_location_info(nodes)
        adjacency_list = create_adjacency_list(line_numbers, node_id_to_ln, edges,
                                               False)

        combined_graph, data_graph = combine_control_and_data_adjacents(adjacency_list)
        pdg = combined_graph_to_dict(combined_graph, src)

        call_slices_bdir = []
        all_slices = []
        file_idx = 0
        print(call_lines)
        new_xfg_list = []
        for line in call_lines:
            line = str(line)
            xfg = xfg_generator(pdg, line)
            if xfg == None:
                continue
            new_xfg = dict()
            xfg_nodes = xfg['nodes']
            xfg_edges = xfg['edges']
            new_xfg_nodes = list()
            nodes_line = list()
            xfg_lines = list()
            new_xfg_edges = list()
            if len(xfg_nodes) == 0:
                continue
            for node in xfg_nodes:
                new_xfg_nodes.append(str(file_idx)+'_'+str(node['line']))
                xfg_lines.append(str(node['line']))
                nodes_line.append(node['label'])
            for edge in xfg_edges:
                new_xfg_edges.append([edge['source'], edge['target']])
            new_xfg['nodes-lineNo'] = new_xfg_nodes
            new_xfg['keyLine'] = str(file_idx)+'_'+line   
            new_xfg['edges-No'] = new_xfg_edges
            new_xfg['target'] = 0
            new_xfg['filePathList'] = [src]
            new_xfg['nodes-line'] = nodes_line
            new_xfg['nodes-line-sym'] = tokenize_gadget_tolist(clean_gadget(nodes_line, sensi_api_set))
                   
            # print(new_xfg)
            new_xfg_list.append(new_xfg)
    #去重
    md5Dict = uniqueDir(new_xfg_list)
    xfgs = writeBigJson(md5Dict)
    
    return xfgs


  

        
