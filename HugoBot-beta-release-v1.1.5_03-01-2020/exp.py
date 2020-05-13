from cli import cli
from constants import MethodsNames


def generate_paa_std_coef_string(paa=1, std_coef=None):
    return f'{"" if paa == 1 else str(paa) + "paa_"}' \
        f'{"" if not std_coef else str(std_coef) + "std_"}'


""" You can use these functions to generate a name for each run.
    Note that runs with the same name will overwrite each other, 
    so pay attention and give a unique name for each run """


def generate_discretization_name(method, nb_bins, max_gap, paa=1, std_coef=None):
    """
    Generates a name to add to the discretization to allow organization of the experiments you perform
    The name will be used as the folder name, and will be concatenated to each result file
    :param method: string, use MethodNames - it contains all the possible methods
    :param nb_bins: int, the number of bins
    :param max_gap: int, the maximum gap between two points to create an interval
    :param paa: int, optional*, the window size by which to perform PAA
    :param std_coef: int, optional*, the standard deviation coefficient by which to remove outliers
    :return: string, a name for the run
    """
    return f'{method}_{nb_bins}bins_{generate_paa_std_coef_string(paa, std_coef)}{max_gap}mg'


def generate_knowledge_based_name(max_gap, paa=1, std_coef=None, identifier=''):
    """
    Same description as above - but generates a name for knowledge-based discretization
    :param max_gap: int, the maximum gap between two points to create an interval
    :param paa: int, optional*, the window size by which to perform PAA
    :param std_coef: int, optional*, the standard deviation coefficient by which to remove outliers
    :param identifier: string, optional* any string that uniquely identifies this run or its properties
    :return: string, a name for the run
    """
    return f'{MethodsNames.KnowledgeBased}_{generate_paa_std_coef_string(paa, std_coef)}' \
        f'{max_gap}mg{"_" + identifier if identifier else identifier}'


def generate_gradient_name(gradient_window_size, max_gap, paa=1, std_coef=None, identifier=''):
    """
    Same description as above - but generates a name for gradient discretization
    :param gradient_window_size: int, the size of the window by which to calculate linear regression
    :param max_gap: int, the maximum gap between two points to create an interval
    :param paa: int, optional*, the window size by which to perform PAA
    :param std_coef: int, optional*, the standard deviation coefficient by which to remove outliers
    :param identifier: string, optional* any string that uniquely identifies this run or its properties
    :return: string, a name for the run
    """
    return f'{MethodsNames.Gradient}_{gradient_window_size}window_' \
        f'{generate_paa_std_coef_string(paa, std_coef)}{max_gap}mg{"_" + identifier if identifier else identifier}'


# The input path should point to a dataset file
input_path = r'Datasets/FAGender/FAGender.csv'
# The output path should be a folder path
output_path = r'Datasets/FAGender'
name = 'some-name-for-this-run'  # this name will show up in all the files created by this run in the output folder
method = MethodsNames.TD4CCosine  # method name can be chosen from MethodNames class
nb_bins = 3
max_gap = 1
paa = 3
std_coef = 2

path_to_preprocessing_params_df = r'Datasets/FAGender/preprocessing.csv'
path_to_temporal_abstraction_params_df = r'Datasets/FAGender/temporal_abstraction.csv'

# running discretization per-dataset of TD4C-cosine
cli(['temporal-abstraction', '-n', name, input_path, output_path, 'per-dataset', '-paa', paa, '-std', std_coef,
     str(max_gap), 'discretization', method, str(nb_bins)])

# running discretization per-dataset of TD4C-cosine with K-Fold of 5 folds
cli(['temporal-abstraction', '-n', name, '--kfold', '5', input_path, output_path, 'per-dataset', str(max_gap),
     'discretization',
     method, str(nb_bins)])

# running knowledge-based discretization per-dataset
cli(['temporal-abstraction', '-n', name, input_path, output_path, 'per-dataset', str(max_gap),
     MethodsNames.KnowledgeBased, path_to_states_file])

""" Note: states are in angles (from -90 to 90) """

# running gradient using a states file
cli(['temporal-abstraction', '-n', name, input_path, output_path, 'per-dataset', str(max_gap),
     MethodsNames.Gradient, gradient_window_size, '--states-path', path_to_states_file])

# running gradient using a list of cutoffs
cli(['temporal-abstraction', '-n', name, input_path, output_path, 'per-dataset', str(max_gap),
     MethodsNames.Gradient, gradient_window_size, '--states-list', '1 2 3'])

# running discretization per-property
cli(['temporal-abstraction', '-n', name, input_path, output_path, 'per-property', path_to_preprocessing_params_df,
     path_to_temporal_abstraction_params_df])

"""  running discretization per-property with a states file (to be used
     by knowledge-based algorithms such as gradient and knowledge-based) """
cli(['temporal-abstraction', '-n', name, input_path, output_path, 'per-property', path_to_preprocessing_params_df,
     path_to_temporal_abstraction_params_df, '--states-file', path_to_states_file])

# running results-union
cli(['results-union', path_to_states_file_1, path_to_KL_file_1, path_to_states_file_2, path_to_KL_file_2,
     path_to_output_dir])
