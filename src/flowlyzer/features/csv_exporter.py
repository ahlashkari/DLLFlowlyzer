

import os
import pandas as pd
import logging
from pathlib import Path
from typing import Optional, Tuple
import numpy as np
from .feature_extractor import FeatureExtractor

class CSVExporter:

    def __init__(self, output_dir: str = "Results"):

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.logger = logging.getLogger(__name__)
        self.feature_extractor = FeatureExtractor()

    def export_flows(self, flows_df: pd.DataFrame,
                    separate_layers: bool = False,
                    base_filename: str = "features") -> Tuple[str, Optional[str], Optional[str]]:

        try:
            if flows_df.empty:
                self.logger.warning("No flows to export")
                return None, None, None

            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")

            combined_file = None
            layer2_file = None
            layer3_file = None

            if separate_layers:
                layer2_df, layer3_df = self.feature_extractor.separate_layer2_layer3(flows_df)

                if not layer2_df.empty:
                    layer2_file = self.output_dir / f"{base_filename}_layer2_{timestamp}.csv"
                    layer2_df.to_csv(layer2_file, index=False)
                    self.logger.info(f"Exported {len(layer2_df)} Layer 2 flows to {layer2_file}")

                if not layer3_df.empty:
                    layer3_file = self.output_dir / f"{base_filename}_layer3_{timestamp}.csv"
                    layer3_df.to_csv(layer3_file, index=False)
                    self.logger.info(f"Exported {len(layer3_df)} Layer 3 flows to {layer3_file}")

                combined_file = self.output_dir / f"{base_filename}_combined_{timestamp}.csv"
                flows_df.to_csv(combined_file, index=False)
                self.logger.info(f"Exported {len(flows_df)} total flows to {combined_file}")

            else:
                combined_file = self.output_dir / f"{base_filename}_{timestamp}.csv"
                flows_df.to_csv(combined_file, index=False)
                self.logger.info(f"Exported {len(flows_df)} flows to {combined_file}")

            return str(combined_file), str(layer2_file) if layer2_file else None, str(layer3_file) if layer3_file else None

        except Exception as e:
            self.logger.error(f"Error exporting flows to CSV: {e}")
            raise

    def export_with_metadata(self, flows_df: pd.DataFrame,
                           processing_stats: dict,
                           separate_layers: bool = False,
                           base_filename: str = "features") -> dict:

        try:
            combined_file, layer2_file, layer3_file = self.export_flows(
                flows_df, separate_layers, base_filename
            )

            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            metadata_file = self.output_dir / f"{base_filename}_metadata_{timestamp}.txt"

            with open(metadata_file, 'w') as f:
                f.write("DLL Flowlyzer Export Metadata\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Export Time: {pd.Timestamp.now()}\n")
                f.write(f"Total Flows: {len(flows_df)}\n")
                f.write(f"Separate Layers: {separate_layers}\n\n")

                f.write("Processing Statistics:\n")
                f.write("-" * 20 + "\n")
                for key, value in processing_stats.items():
                    f.write(f"{key}: {value}\n")

                f.write("\nFlow Label Distribution:\n")
                f.write("-" * 25 + "\n")
                if 'label' in flows_df.columns:
                    label_counts = flows_df['label'].value_counts()
                    for label, count in label_counts.items():
                        f.write(f"{label}: {count}\n")

                f.write("\nFeature Columns:\n")
                f.write("-" * 15 + "\n")
                for i, col in enumerate(flows_df.columns, 1):
                    f.write(f"{i:3d}. {col}\n")

            export_info = {
                'combined_file': combined_file,
                'layer2_file': layer2_file,
                'layer3_file': layer3_file,
                'metadata_file': str(metadata_file),
                'total_flows': len(flows_df),
                'export_timestamp': timestamp,
            }

            self.logger.info(f"Export completed with metadata: {metadata_file}")

            return export_info

        except Exception as e:
            self.logger.error(f"Error exporting with metadata: {e}")
            raise

    def create_feature_summary(self, flows_df: pd.DataFrame) -> str:

        try:
            timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
            summary_file = self.output_dir / f"feature_summary_{timestamp}.txt"

            with open(summary_file, 'w') as f:
                f.write("DLL Flowlyzer Feature Summary\n")
                f.write("=" * 35 + "\n\n")

                f.write(f"Dataset Shape: {flows_df.shape}\n")
                f.write(f"Total Flows: {len(flows_df)}\n")
                f.write(f"Total Features: {len(flows_df.columns)}\n\n")

                f.write("Missing Values Analysis:\n")
                f.write("-" * 25 + "\n")
                missing_stats = flows_df.isnull().sum()
                missing_percent = (missing_stats / len(flows_df)) * 100

                for col in flows_df.columns:
                    if missing_stats[col] > 0:
                        f.write(f"{col}: {missing_stats[col]} ({missing_percent[col]:.1f}%)\n")

                f.write("\nNumeric Feature Statistics:\n")
                f.write("-" * 30 + "\n")
                numeric_cols = flows_df.select_dtypes(include=[np.number]).columns
                desc_stats = flows_df[numeric_cols].describe()
                f.write(desc_stats.to_string())

                f.write("\n\nCategorical Feature Statistics:\n")
                f.write("-" * 35 + "\n")
                categorical_cols = flows_df.select_dtypes(include=['object', 'bool']).columns

                for col in categorical_cols[:10]:
                    value_counts = flows_df[col].value_counts().head(5)
                    f.write(f"\n{col}:\n")
                    for value, count in value_counts.items():
                        f.write(f"  {value}: {count}\n")

            self.logger.info(f"Feature summary created: {summary_file}")
            return str(summary_file)

        except Exception as e:
            self.logger.error(f"Error creating feature summary: {e}")
            raise

    def append_to_csv(self, flows_df: pd.DataFrame, csv_file_path: str) -> bool:

        try:
            if flows_df.empty:
                self.logger.warning("No flows to append")
                return True

            if os.path.exists(csv_file_path):

                existing_df = pd.read_csv(csv_file_path, nrows=0)

                if set(flows_df.columns) != set(existing_df.columns):

                    flows_df = flows_df.reindex(columns=existing_df.columns, fill_value=0)

                flows_df.to_csv(csv_file_path, mode='a', header=False, index=False)
                self.logger.info(f"Appended {len(flows_df)} flows to {csv_file_path}")
            else:

                flows_df.to_csv(csv_file_path, index=False)
                self.logger.info(f"Created new CSV with {len(flows_df)} flows: {csv_file_path}")

            return True

        except Exception as e:
            self.logger.error(f"Error appending to CSV {csv_file_path}: {e}")
            return False

    def export_flows_batch(self, flows_df: pd.DataFrame,
                          batch_files: dict,
                          separate_layers: bool = False) -> dict:

        try:
            if flows_df.empty:
                return batch_files

            combined_file = batch_files.get('combined')
            if combined_file:
                self.append_to_csv(flows_df, combined_file)

            if separate_layers:
                layer2_df, layer3_df = self.feature_extractor.separate_layer2_layer3(flows_df)

                if not layer2_df.empty and batch_files.get('layer2'):
                    self.append_to_csv(layer2_df, batch_files['layer2'])

                if not layer3_df.empty and batch_files.get('layer3'):
                    self.append_to_csv(layer3_df, batch_files['layer3'])

            return batch_files

        except Exception as e:
            self.logger.error(f"Error in batch export: {e}")
            raise

    def create_batch_files(self, base_filename: str, separate_layers: bool = False) -> dict:

        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")

        batch_files = {
            'combined': str(self.output_dir / f"{base_filename}_combined_{timestamp}.csv")
        }

        if separate_layers:
            batch_files['layer2'] = str(self.output_dir / f"{base_filename}_layer2_{timestamp}.csv")
            batch_files['layer3'] = str(self.output_dir / f"{base_filename}_layer3_{timestamp}.csv")
        else:
            batch_files['layer2'] = None
            batch_files['layer3'] = None

        return batch_files

    def validate_export(self, file_path: str) -> bool:

        try:
            if not os.path.exists(file_path):
                self.logger.error(f"Export file does not exist: {file_path}")
                return False

            df = pd.read_csv(file_path)

            if df.empty:
                self.logger.warning(f"Export file is empty: {file_path}")
                return False

            required_cols = ['connection', 'num_frame', 'label']
            missing_cols = [col for col in required_cols if col not in df.columns]

            if missing_cols:
                self.logger.error(f"Missing required columns in {file_path}: {missing_cols}")
                return False

            self.logger.info(f"Export file validation passed: {file_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error validating export file {file_path}: {e}")
            return False