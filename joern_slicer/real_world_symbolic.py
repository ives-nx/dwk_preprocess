''' brief description

detailed description

@Time    : 2020/4/22 20:05
@Author  : Xiao Cheng
@FileName: real_world_symbolic.py
@Software: PyCharm
'''
project = "redis"
import re
from vectorize_gadget import GadgetVectorizer
import os
import json
import sys




def get_sensiApi_list_for_sard(cwe_id):
    path = 'resource/CWE'+str(cwe_id)+'_api.json'
    json_dic = list()
    with open(path, 'r', encoding='utf8')as f:
        json_dic = json.load(f)
        f.close()
    
    api_list = [i[0] for i in json_dic[0:100]]
    return api_list

def replaceComment(matchobj):
    if not matchobj:
        return

    matchstr = matchobj.group(0)
    if matchstr.startswith('"') and matchstr.endswith('"'):
        return matchstr
    else:
        return ''


def removeComment(inputstr):
    singleLineCommentExp = r'//[^\n]*'
    multiLinecommentExp = r'/\*.*?\*/'
    literalStringExp = r'"([^\\"]|\\.)*?"'  # . should match newline, for scenario like multiline literal string

    patternExp = literalStringExp + '|' + singleLineCommentExp + '|' + multiLinecommentExp
    codeString = re.sub(patternExp, replaceComment, inputstr, 0, re.MULTILINE | re.DOTALL)
    return codeString


# input is a list of string lines
def clean_gadget(gadget , sensi_api_set):
    # keywords up to C11 and C++17; immutable set
    keywords = frozenset({'__asm', '__builtin', '__cdecl', '__declspec', '__except', '__export', '__far16', '__far32',
                      '__fastcall', '__finally', '__import', '__inline', '__int16', '__int32', '__int64', '__int8',
                      '__leave', '__optlink', '__packed', '__pascal', '__stdcall', '__system', '__thread', '__try',
                      '__unaligned', '_asm', '_Builtin', '_Cdecl', '_declspec', '_except', '_Export', '_Far16',
                      '_Far32', '_Fastcall', '_finally', '_Import', '_inline', '_int16', '_int32', '_int64',
                      '_int8', '_leave', '_Optlink', '_Packed', '_Pascal', '_stdcall', '_System', '_try', 'alignas',
                      'alignof', 'and', 'and_eq', 'asm', 'auto', 'bitand', 'bitor', 'bool', 'break', 'case',
                      'catch', 'char', 'char16_t', 'char32_t', 'class', 'compl', 'const', 'const_cast', 'constexpr',
                      'continue', 'decltype', 'default', 'delete', 'do', 'double', 'dynamic_cast', 'else', 'enum',
                      'explicit', 'export', 'extern', 'false', 'final', 'float', 'for', 'friend', 'goto', 'if',
                      'inline', 'int', 'long', 'mutable', 'namespace', 'new', 'noexcept', 'not', 'not_eq', 'nullptr',
                      'operator', 'or', 'or_eq', 'override', 'private', 'protected', 'public', 'register',
                      'reinterpret_cast', 'return', 'short', 'signed', 'sizeof', 'static', 'static_assert',
                      'static_cast', 'struct', 'switch', 'template', 'this', 'thread_local', 'throw', 'true', 'try',
                      'typedef', 'typeid', 'typename', 'union', 'unsigned', 'using', 'virtual', 'void', 'volatile',
                      'wchar_t', 'while', 'xor', 'xor_eq', 'NULL'})


    # holds known non-user-defined functions; immutable set
    main_set = frozenset({'main'})
    # arguments in main function; immutable set
    main_args = frozenset({'argc', 'argv'})
    a = []
    a = sensi_api_set
    keywords = keywords.union(a)
    # dictionary; map function name to symbol name + number
    fun_symbols = {}
    # dictionary; map variable name to symbol name + number
    var_symbols = {}

    fun_count = 1
    var_count = 1

    # regular expression to catch multi-line comment
    rx_comment = re.compile('\*/\s*$')
    # regular expression to find function name candidates
    rx_fun = re.compile(r'\b([_A-Za-z]\w*)\b(?=\s*\()')
    # regular expression to find variable name candidates
    # rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?!\s*\()')
    rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()')

    # final cleaned gadget output to return to interface
    cleaned_gadget = []

    for line in gadget:
        # process if not the header line and not a multi-line commented line
        if not (rx_comment.search(line) is None):
            line = removeComment(line)
        # remove all string literals (keep the quotes)
        nostrlit_line = re.sub(r'".*?"', '""', line)
        # remove all character literals
        nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)
        # replace any non-ASCII characters with empty string
        ascii_line = re.sub(r'[^\x00-\x7f]', r'', nocharlit_line)

        # return, in order, all regex matches at string list; preserves order for semantics
        user_fun = rx_fun.findall(ascii_line)
        user_var = rx_var.findall(ascii_line)

        # Could easily make a "clean gadget" type class to prevent duplicate functionality
        # of creating/comparing symbol names for functions and variables in much the same way.
        # The comparison frozenset, symbol dictionaries, and counters would be class scope.
        # So would only need to pass a string list and a string literal for symbol names to
        # another function.
        for fun_name in user_fun:
            if len({fun_name}.difference(main_set)) != 0 and len({fun_name}.difference(keywords)) != 0:
                # DEBUG
                # print('comparing ' + str(fun_name + ' to ' + str(main_set)))
                # print(fun_name + ' diff len from main is ' + str(len({fun_name}.difference(main_set))))
                # print('comparing ' + str(fun_name + ' to ' + str(keywords)))
                # print(fun_name + ' diff len from keywords is ' + str(len({fun_name}.difference(keywords))))
                ###
                # check to see if function name already in dictionary
                if fun_name not in fun_symbols.keys():
                    fun_symbols[fun_name] = 'FUN' + str(fun_count)
                    fun_count += 1
                # ensure that only function name gets replaced (no variable name with same
                # identifier); uses positive lookforward
                ascii_line = re.sub(r'\b(' + fun_name + r')\b(?=\s*\()', fun_symbols[fun_name], ascii_line)

        for var_name in user_var:
            # next line is the nuanced difference between fun_name and var_name
            if len({var_name}.difference(keywords)) != 0 and len({var_name}.difference(main_args)) != 0:
                # DEBUG
                # print('comparing ' + str(var_name + ' to ' + str(keywords)))
                # print(var_name + ' diff len from keywords is ' + str(len({var_name}.difference(keywords))))
                # print('comparing ' + str(var_name + ' to ' + str(main_args)))
                # print(var_name + ' diff len from main args is ' + str(len({var_name}.difference(main_args))))
                ###
                # check to see if variable name already in dictionary
                if var_name not in var_symbols.keys():
                    var_symbols[var_name] = 'VAR' + str(var_count)
                    var_count += 1
                # ensure that only variable name gets replaced (no function name with same
                # identifier); uses negative lookforward
                ascii_line = re.sub(r'\b(' + var_name + r')\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()', \
                                    var_symbols[var_name], ascii_line)

        cleaned_gadget.append(ascii_line)
    # return the list of cleaned lines
    return cleaned_gadget


def tokenize_gadget_tolist(gadget):
    '''

    :param gadget:
    :return:
    '''
    tokenized = []
    for line in gadget:
        tokens = GadgetVectorizer.tokenize(line)
        tokenized.append(" ".join(tokens))

    return tokenized


def symbolzeJson(inputJsonDir, outputJsonDir):
    '''

    :param inputJsonDir:
    :param outputJsonDir:
    :return:
    '''
    commitids = os.listdir(inputJsonDir)
    for commitid in commitids:
        bcs = os.listdir(inputJsonDir + commitid)
        if (len(bcs) != 0):
            if (not os.path.exists(outputJsonDir + commitid)):
                os.mkdir(outputJsonDir + commitid)
            for bc in bcs:
                jsonPath = inputJsonDir + commitid + "/" + bc
                outJson = outputJsonDir + commitid + "/" + bc
                if(os.path.exists(outJson)):
                    print("{} exists - skip".format(outJson))
                    continue
                print("processing - {}".format(jsonPath))
                with open(jsonPath, "r", encoding="utf-8", errors="ignore") as f:
                    cfgs = json.load(f)
                    for idx in range(len(cfgs)):
                        cfg = cfgs[idx]
                        cfg["nodes-line-sym"] = tokenize_gadget_tolist(clean_gadget(cfg["nodes-line"]))
                    with open(outJson, 'w', encoding="utf-8") as ff:
                        json.dump(cfgs, ff, indent=2)
                print("end processing - {}".format(jsonPath))


def test():
    test_gadget = ['231 151712/shm_setup.c inputfunc 11',
                   'int main(int argc, char **argv) {',
                   'while ((c = getopt(argc, argv, "k:s:m:o:h")) != -1) {',
                   'switch(c) {']

    test_gadget2 = ['278 151587/ffmpeg.c inputfunc 3159', 'int main(int argc,char **argv)',
                    'parse_loglevel(argc,argv,options);', 'if (argc > 1 && !strcmp(argv[1],"-d")) {',
                    'argc--;', 'argv++;', 'show_banner(argc,argv,options);',
                    'ret = ffmpeg_parse_options(argc,argv);', 'if (ret < 0) {']

    test_gadget3 = ['invalid_memory_access_012_s_001 *s;',
                    's = (invalid_memory_access_012_s_001 *)calloc(1,sizeof(invalid_memory_access_012_s_001));',
                    's->a = 20;', 's->b = 20;', 's->uninit = 20;', 'free(s);]']

    test_gadget4 = [
        "void doGet(HttpServletRequest req,HttpServletResponse res)",
        "res.setContentType('text/html')"
    ]

    test_gadgetline = ['function(File file, Buffer buff)', 'this is a comment test */']

    split_test = 'printf ( " " , variable ++  )'.split()

    # print(clean_gadget(test_gadget))
    # print(clean_gadget(test_gadget2))
    # print(clean_gadget(test_gadget3))
    # print(clean_gadget(test_gadgetline))
    # print(split_test)
    print(tokenize_gadget_tolist(clean_gadget(test_gadget4, 79)))
    # inputDir = "F:\\CodingProject\\py_project\\SVFDLDetect\\resources\\test-json\\"
    #
    # outputDir = "F:\\CodingProject\\py_project\\SVFDLDetect\\resources\\test-json3\\"
    # symbolzeJson(inputDir, outputDir)


if __name__ == '__main__':
    # rootdir = "/home/cry/chengxiao/dataset/svf-related/real-world/" + project
    # inputJsonDir = rootdir + "/XFG-raw/"
    # outputJsonDir = rootdir + "/XFG-sym/"

    # symbolzeJson(inputJsonDir, outputJsonDir)
    test()
