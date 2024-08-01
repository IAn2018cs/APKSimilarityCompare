# coding=utf-8
import os

os.environ["LOGURU_LEVEL"] = "CRITICAL"

from androguard.misc import AnalyzeAPK
import hashlib


def get_method_signature(method):
    return method.full_name


def hash_feature(feature):
    return hashlib.md5(feature.encode()).hexdigest()


def get_method_features(method):
    features = set()

    # 添加方法签名作为特征
    features.add(hash_feature(f"signature:{method.full_name}"))

    # 添加API调用作为特征
    for _, call, _ in method.get_xref_to():
        features.add(hash_feature(f"api_call:{call.full_name}"))

    # 添加控制流结构作为特征
    for block in method.get_basic_blocks().gets():
        instruction_count = sum(1 for _ in block.get_instructions())
        features.add(hash_feature(f"block:{instruction_count}"))

    # 添加字符串常量作为特征
    if method.code:
        for instruction in method.get_method().get_instructions():
            if instruction.get_name() in ["const-string", "const-string/jumbo"]:
                string = instruction.cm.vm.get_cm_string(instruction.get_ref_kind())
                features.add(hash_feature(f"string:{string}"))

    return features


def get_method_body(method):
    return ' '.join(instruction.get_name() for instruction in method.get_method().get_instructions())


def analyze_apk(apk_path):
    return AnalyzeAPK(apk_path)


def filter_method(method):
    return method.class_name.startswith('Lwisemate/ai') and 'private' in method.access


def compare_apk_code(apk1_path, apk2_path):
    print(f"Analyzing {os.path.basename(apk1_path)} and {os.path.basename(apk2_path)}...")

    _, _, dx1 = analyze_apk(apk1_path)
    _, _, dx2 = analyze_apk(apk2_path)

    # 获取内部方法
    internal_methods1 = [m for m in dx1.get_internal_methods() if filter_method(m)]
    internal_methods2 = [m for m in dx2.get_internal_methods() if filter_method(m)]

    show_index = 64
    print(f"\nclass_name: \n{internal_methods1[show_index].class_name}\n")
    print(f"method_signature: \n{get_method_signature(internal_methods1[show_index])}\n")
    print(f"access: \n{internal_methods1[show_index].access}\n")
    print(f"method_body: \n{get_method_body(internal_methods1[show_index])}\n")

    # 1. 方法签名比较
    print("\n1. 方法签名比较:")
    signatures1 = set(get_method_signature(m) for m in internal_methods1)
    signatures2 = set(get_method_signature(m) for m in internal_methods2)
    common_signatures = signatures1.intersection(signatures2)
    signature_similarity = len(common_signatures) / max(len(signatures1), len(signatures2))
    print(f"APK 1 内部方法数: {len(signatures1)}")
    print(f"APK 2 内部方法数: {len(signatures2)}")
    print(f"共同方法签名数: {len(common_signatures)}")
    print(f"方法签名相似度: {signature_similarity:.4f}")

    # 2. 方法特征比较
    print("\n2. 方法特征相似度:")
    method_features1 = [get_method_features(m) for m in internal_methods1]
    method_features2 = [get_method_features(m) for m in internal_methods2]

    total_similarity = 0
    for features1 in method_features1:
        max_similarity = max((len(features1 & features2) / len(features1 | features2)
                              for features2 in method_features2), default=0)
        total_similarity += max_similarity

    avg_similarity = total_similarity / len(method_features1) if method_features1 else 0

    print(f"APK 1 方法数: {len(method_features1)}")
    print(f"APK 2 方法数: {len(method_features2)}")
    print(f"平均方法特征相似度: {avg_similarity:.4f}")

    # 3. 类级别比较
    print("\n3. 类级别比较:")
    classes1 = set(m.class_name for m in internal_methods1)
    classes2 = set(m.class_name for m in internal_methods2)
    common_classes = classes1.intersection(classes2)
    class_similarity = len(common_classes) / max(len(classes1), len(classes2))
    print(f"APK 1 类数: {len(classes1)}")
    print(f"APK 2 类数: {len(classes2)}")
    print(f"共同类数: {len(common_classes)}")
    print(f"类相似度: {class_similarity:.4f}")

    # 4. 方法长度分布比较
    print("\n4. 方法长度分布比较:")
    lengths1 = [m.get_length() for m in internal_methods1]
    lengths2 = [m.get_length() for m in internal_methods2]
    avg_length1 = sum(lengths1) / len(lengths1) if lengths1 else 0
    avg_length2 = sum(lengths2) / len(lengths2) if lengths2 else 0
    print(f"APK 1 平均方法长度: {avg_length1:.2f}")
    print(f"APK 2 平均方法长度: {avg_length2:.2f}")
    length_similarity = min(avg_length1, avg_length2) / max(avg_length1, avg_length2) if max(avg_length1,
                                                                                             avg_length2) > 0 else 1
    print(f"方法长度相似度: {length_similarity:.4f}")

    # 5. 基本块比较
    print("\n5. 基本块比较:")
    bb_counts1 = [len(m.get_basic_blocks().gets()) for m in internal_methods1]
    bb_counts2 = [len(m.get_basic_blocks().gets()) for m in internal_methods2]
    avg_bb1 = sum(bb_counts1) / len(bb_counts1) if bb_counts1 else 0
    avg_bb2 = sum(bb_counts2) / len(bb_counts2) if bb_counts2 else 0
    print(f"APK 1 平均基本块数: {avg_bb1:.2f}")
    print(f"APK 2 平均基本块数: {avg_bb2:.2f}")
    bb_similarity = min(avg_bb1, avg_bb2) / max(avg_bb1, avg_bb2) if max(avg_bb1, avg_bb2) > 0 else 1
    print(f"基本块数量相似度: {bb_similarity:.4f}")

    # 总体内部方法相似度评分
    overall_similarity = (
                                 signature_similarity + avg_similarity + class_similarity + length_similarity + bb_similarity) / 5
    print(f"\n总体内部方法相似度评分: {overall_similarity:.4f}")


if __name__ == '__main__':
    # 使用示例
    compare_apk_code("./apks/ai.apk", "./apks/ori.apk")
