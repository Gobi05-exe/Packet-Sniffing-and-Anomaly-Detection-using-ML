import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
import numpy as np
import os
from imblearn.over_sampling import RandomOverSampler

# Print the available flag values for debugging purposes
def print_flag_values(df, column_name):
    unique_values = df[column_name].unique()
    print(f"Unique values in {column_name} column: {sorted(unique_values)}")

# Function to safely load data
def load_data(file_path, default_path):
    try:
        if not os.path.exists(file_path):
            print(f"File {file_path} not found, trying default path {default_path}")
            file_path = default_path
        
        df = pd.read_csv(file_path)
        return df
    except Exception as e:
        print(f"Error loading data from {file_path}: {e}")
        raise

# Function to safely transform categorical features
def safe_transform(column, le, column_name):
    # Create a copy of the column to avoid modifying the original
    column_copy = column.copy()
    
    try:
        return le.transform(column_copy)
    except ValueError as e:
        print(f"Unseen labels encountered in column '{column_name}': {e}")
        
        # Handle unseen labels by setting them to an encoded value
        transformed = np.zeros(len(column_copy), dtype=int)
        for i, val in enumerate(column_copy):
            if val in le.classes_:
                transformed[i] = le.transform([val])[0]
            else:
                # Assign a default value (-1) for unseen labels
                transformed[i] = -1
        
        return transformed

try:
    # Load training dataset
    file_path = "kdd_train.csv"  # Update path if necessary
    df = load_data(file_path, "kdd_train.csv")
    
    # Print unique protocol and flag values for reference
    print_flag_values(df, 'protocol_type')
    print_flag_values(df, 'flag')
    
    # Check if the dataframe has any rows
    if df.empty:
        raise ValueError("The training data file is empty")
    
    # Check if the required columns exist
    required_columns = ['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes',
                       'land', 'wrong_fragment', 'urgent', 'count', 'srv_count', 'labels']
    
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns in training data: {missing_columns}")
    
    # Select Scapy-compatible features
    scapy_features = [
        'duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'count', 'srv_count'
    ]
    
    # Make working copies to avoid modifying the original dataframe
    X = df[scapy_features].copy()
    y = df['labels'].apply(lambda x: 0 if x == 'normal' else 1).astype(int)
    
    # Create a temporary dataframe for additional samples if needed
    additional_samples = pd.DataFrame(columns=X.columns)
    additional_labels = []
    
    # Ensure 'tcp' is in protocol_type classes
    if 'tcp' not in X['protocol_type'].unique():
        new_row = pd.Series([0, 'tcp', 'OTH', 0, 0, 0, 0, 0, 0, 0], index=X.columns)
        additional_samples = pd.concat([additional_samples, pd.DataFrame([new_row])], ignore_index=True)
        additional_labels.append(0)  # Add corresponding 'normal' label
        print("Added dummy 'tcp' protocol record for encoder compatibility")
    
    # Ensure all flag types used in our generator/sniffer are present
    needed_flags = ['S', 'SF', 'REJ', 'RSTO', 'RSTOS0', 'SH', 'RSTRH', 'OTH']
    for flag in needed_flags:
        if flag not in X['flag'].unique():
            new_row = pd.Series([0, 'tcp', flag, 0, 0, 0, 0, 0, 0, 0], index=X.columns)
            additional_samples = pd.concat([additional_samples, pd.DataFrame([new_row])], ignore_index=True)
            additional_labels.append(0)  # Add corresponding 'normal' label
            print(f"Added dummy '{flag}' flag record for encoder compatibility")
    
    # Add the additional samples and labels if any were created
    if not additional_samples.empty:
        X = pd.concat([X, additional_samples], ignore_index=True)
        y = pd.concat([y, pd.Series(additional_labels)], ignore_index=True)
        print(f"Added {len(additional_samples)} dummy samples for encoder compatibility")
        print(f"Total samples: {len(X)}, Total labels: {len(y)}")
    
    # Verify X and y have the same length
    if len(X) != len(y):
        raise ValueError(f"Inconsistent number of samples: X has {len(X)} rows but y has {len(y)} elements")
    
    # Encode categorical features with LabelEncoder
    le_protocol = LabelEncoder()
    le_flag = LabelEncoder()
    
    # Fit and transform
    X['protocol_type'] = le_protocol.fit_transform(X['protocol_type'])
    X['flag'] = le_flag.fit_transform(X['flag'])
    
    # Print encoded mapping for reference
    print("Protocol type mapping:")
    for i, label in enumerate(le_protocol.classes_):
        print(f"  {label} -> {i}")
    
    print("Flag mapping:")
    for i, label in enumerate(le_flag.classes_):
        print(f"  {label} -> {i}")
    
    # Convert all features to numeric and handle missing values
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Balance the dataset using oversampling
    ros = RandomOverSampler(random_state=42)
    X_resampled, y_resampled = ros.fit_resample(X, y)

    print("Original class distribution:")
    print(y.value_counts())
    print("Resampled class distribution:")
    print(pd.Series(y_resampled).value_counts())

    # Replace original X and y with balanced versions
    X = X_resampled
    y = y_resampled

    # Split data into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Train Random Forest Classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Save the model and encoders
    joblib.dump(model, 'random_forest_model.pkl')
    joblib.dump(le_protocol, 'le_protocol.pkl')
    joblib.dump(le_flag, 'le_flag.pkl')
    
    # Predict and evaluate on the training set
    y_pred_train = model.predict(X_test)
    mse_train = mean_squared_error(y_test, y_pred_train)
    
    # Print training evaluation metrics
    print(f"Training Mean Squared Error: {mse_train:.6f}")
    print("Classification Report (Training Data):")
    print(classification_report(y_test, y_pred_train))
    
    # Load the new test dataset
    test_file_path = "kdd_test.csv"  # Update path if necessary
    df_test = load_data(test_file_path, "kdd_test.csv")
    
    # Check if the test dataframe has any rows
    if df_test.empty:
        raise ValueError("The test data file is empty")
    
    # Check if the required columns exist in test data
    missing_columns = [col for col in required_columns if col not in df_test.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns in test data: {missing_columns}")
    
    # Prepare the test features and target variable
    X_test_new = df_test[scapy_features].copy()
    
    # Encode categorical features in the test data
    X_test_new['protocol_type'] = safe_transform(X_test_new['protocol_type'], le_protocol, 'protocol_type')
    X_test_new['flag'] = safe_transform(X_test_new['flag'], le_flag, 'flag')
    
    # Convert all features to numeric and handle missing values
    X_test_new = X_test_new.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    y_test_new = df_test['labels'].apply(lambda x: 0 if x == 'normal' else 1).astype(int)
    
    # Predict on the new test set
    model_loaded = joblib.load('random_forest_model.pkl')
    y_pred_new = model_loaded.predict(X_test_new)
    
    # Evaluate on the new test set
    mse_new = mean_squared_error(y_test_new, y_pred_new)
    
    # Print test evaluation metrics
    print(f"Test Mean Squared Error: {mse_new:.6f}")
    print("Classification Report (Test Data):")
    print(classification_report(y_test_new, y_pred_new))
    
    # Create and save visualization of the classification report
    report = classification_report(y_test_new, y_pred_new, output_dict=True)
    report_df = pd.DataFrame(report).transpose()
    
    plt.figure(figsize=(10, 6))
    sns.heatmap(report_df.iloc[:-1, :].T, annot=True, cmap='Blues', fmt='.2f')
    plt.title('Classification Report (Test Data)')
    plt.tight_layout()
    
    # Save the plot
    plt.savefig('classification_report_test.png')
    plt.close()
    
    # Add confusion matrix visualization
    cm = confusion_matrix(y_test_new, y_pred_new)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix (Test Data)')
    plt.xlabel('Predicted Labels')
    plt.ylabel('True Labels')
    plt.tight_layout()
    plt.savefig('confusion_matrix_test.png')
    
    print("Training and evaluation completed successfully.")
    
except Exception as e:
    print(f"An error occurred: {e}")