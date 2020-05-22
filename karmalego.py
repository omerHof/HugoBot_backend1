from KarmaLego_Framework import RunKarmaLego
import os


def create_directory(dataset_name, discretization_id, kl_id):
    path = dataset_name + "/" + discretization_id + "/" + kl_id
    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)
    return path

def ranKarma(dataset_name, discretization_id, KL_id, support_vec, num_relations, max_gap, epsilon, max_tirp_length, index_same):
    create_directory(dataset_name, discretization_id, KL_id)
    directory_path = dataset_name + "/" + discretization_id
    for filename in os.listdir('C:/Users/yonatan/PycharmProjects/HugoBotServer/' + directory_path):
        if filename.endswith(".txt"):
            path = 'C:/Users/yonatan/PycharmProjects/HugoBotServer/' + directory_path + '/' + filename
            out_path = 'C:/Users/yonatan/PycharmProjects/HugoBotServer/' + directory_path + '/' + KL_id + '/' + filename
            print_output_incrementally = True
            entity_ids_num = 2
            semicolon_end = True
            need_one_sized = True
            lego_0, karma_0 = RunKarmaLego.runKarmaLego(time_intervals_path=path, output_path=out_path,
                                                        index_same=index_same, epsilon=epsilon,
                                                        incremental_output=print_output_incrementally,
                                                        min_ver_support=support_vec,
                                                        num_relations=num_relations, skip_followers=False,
                                                        max_gap=max_gap, label=0,
                                                        max_tirp_length=max_tirp_length, num_comma=2,
                                                        entity_ids_num=entity_ids_num,
                                                        semicolon_end=semicolon_end, need_one_sized=need_one_sized)
            if not print_output_incrementally:
                lego_0.print_frequent_tirps(out_path)
        else:
            continue