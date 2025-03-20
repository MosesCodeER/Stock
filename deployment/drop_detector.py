#!/usr/bin/env python3
"""
Drop Detection Module - Enhanced algorithms for detecting significant stock price drops
"""

import sys
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Add path for data API access
sys.path.append('/opt/.manus/.sandbox-runtime')
from data_api import ApiClient

class DropDetector:
    def __init__(self):
        """Initialize the DropDetector class with Yahoo Finance API client"""
        self.client = ApiClient()
    
    def detect_drops(self, symbol, threshold=-0.05, days=30, consecutive_days=False):
        """
        Detect significant price drops for a stock with enhanced detection
        
        Args:
            symbol (str): Stock symbol
            threshold (float): Drop threshold (default -5%)
            days (int): Number of days to look back
            consecutive_days (bool): Whether to detect drops over consecutive days
            
        Returns:
            dict: Drop detection results
        """
        try:
            # Call Yahoo Finance API to get stock chart data
            stock_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                             query={'symbol': symbol, 
                                                   'interval': '1d', 
                                                   'range': f"{days}d",
                                                   'includeAdjustedClose': True})
            
            # Process the response
            if not stock_data or 'chart' not in stock_data or 'result' not in stock_data['chart']:
                return {'error': f"Failed to fetch data for {symbol}"}
            
            result = stock_data['chart']['result'][0]
            
            # Extract timestamp and price data
            timestamps = result['timestamp']
            indicators = result['indicators']
            
            # Get quote data (open, high, low, close, volume)
            quote = indicators['quote'][0]
            close_prices = quote.get('close', [])
            
            # Convert timestamps to dates
            dates = [datetime.fromtimestamp(ts).strftime('%Y-%m-%d') for ts in timestamps]
            
            # Create DataFrame for analysis
            df = pd.DataFrame({
                'date': dates,
                'timestamp': timestamps,
                'close': close_prices
            })
            
            # Remove rows with None values
            df = df.dropna(subset=['close'])
            
            # Calculate daily returns
            df['daily_return'] = df['close'].pct_change()
            
            # Find single-day drops
            single_day_drops = []
            for idx, row in df.iterrows():
                if idx > 0 and row['daily_return'] is not None and row['daily_return'] <= threshold:
                    single_day_drops.append({
                        'date': row['date'],
                        'previous_close': df.iloc[idx-1]['close'],
                        'close': row['close'],
                        'drop_percentage': round(row['daily_return'] * 100, 2),
                        'type': 'single_day'
                    })
            
            # Find consecutive day drops if requested
            consecutive_drops = []
            if consecutive_days and len(df) > 2:
                # Calculate cumulative returns over rolling windows
                for window in range(2, min(6, len(df))):  # Look for 2-5 day drops
                    df[f'return_{window}d'] = df['close'].pct_change(periods=window)
                    
                    for idx, row in df.iterrows():
                        if idx >= window and row[f'return_{window}d'] is not None and row[f'return_{window}d'] <= threshold:
                            # Only include if not already part of a single-day drop
                            if not any(d['date'] == row['date'] for d in single_day_drops):
                                consecutive_drops.append({
                                    'date': row['date'],
                                    'start_date': df.iloc[idx-window]['date'],
                                    'start_close': df.iloc[idx-window]['close'],
                                    'close': row['close'],
                                    'drop_percentage': round(row[f'return_{window}d'] * 100, 2),
                                    'days': window,
                                    'type': 'consecutive'
                                })
            
            # Combine all drops
            all_drops = single_day_drops + consecutive_drops
            
            # Sort by date (most recent first)
            all_drops.sort(key=lambda x: x['date'], reverse=True)
            
            # Calculate volatility metrics
            volatility = None
            if len(df) > 1:
                df['daily_return'] = df['daily_return'].fillna(0)
                volatility = round(df['daily_return'].std() * 100, 2)  # Standard deviation as percentage
            
            # Calculate maximum drawdown
            max_drawdown = None
            if len(df) > 1:
                df['cummax'] = df['close'].cummax()
                df['drawdown'] = (df['close'] - df['cummax']) / df['cummax']
                max_drawdown = round(df['drawdown'].min() * 100, 2)
            
            return {
                'symbol': symbol,
                'threshold': threshold * 100,
                'period_days': days,
                'drops_detected': len(all_drops),
                'single_day_drops': len(single_day_drops),
                'consecutive_drops': len(consecutive_drops),
                'volatility': volatility,
                'max_drawdown': max_drawdown,
                'drops': all_drops
            }
            
        except Exception as e:
            return {'error': f"Error detecting drops for {symbol}: {str(e)}"}
    
    def analyze_market_conditions(self, symbol, index_symbol='^GSPC', days=90):
        """
        Analyze market conditions to determine if drops are stock-specific or market-wide
        
        Args:
            symbol (str): Stock symbol
            index_symbol (str): Market index symbol (default S&P 500)
            days (int): Number of days to analyze
            
        Returns:
            dict: Market condition analysis
        """
        try:
            # Get stock data
            stock_drops = self.detect_drops(symbol, threshold=-0.03, days=days)
            
            # Get index data
            index_drops = self.detect_drops(index_symbol, threshold=-0.02, days=days)
            
            # Find correlated drops (drops that occurred on the same day)
            correlated_drops = []
            market_specific_drops = []
            
            if 'drops' in stock_drops and 'drops' in index_drops:
                stock_drop_dates = {drop['date']: drop for drop in stock_drops['drops'] if drop['type'] == 'single_day'}
                index_drop_dates = {drop['date']: drop for drop in index_drops['drops'] if drop['type'] == 'single_day'}
                
                # Find drops that occurred on the same day
                for date in stock_drop_dates:
                    if date in index_drop_dates:
                        correlated_drops.append({
                            'date': date,
                            'stock_drop': stock_drop_dates[date]['drop_percentage'],
                            'index_drop': index_drop_dates[date]['drop_percentage'],
                            'difference': round(stock_drop_dates[date]['drop_percentage'] - index_drop_dates[date]['drop_percentage'], 2)
                        })
                    else:
                        market_specific_drops.append(stock_drop_dates[date])
            
            # Calculate correlation between stock and index
            correlation = None
            try:
                # Get stock and index data for correlation calculation
                stock_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                                query={'symbol': symbol, 
                                                      'interval': '1d', 
                                                      'range': f"{days}d"})
                
                index_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                                query={'symbol': index_symbol, 
                                                      'interval': '1d', 
                                                      'range': f"{days}d"})
                
                if (stock_data and index_data and 
                    'chart' in stock_data and 'chart' in index_data and 
                    'result' in stock_data['chart'] and 'result' in index_data['chart']):
                    
                    stock_close = stock_data['chart']['result'][0]['indicators']['quote'][0]['close']
                    index_close = index_data['chart']['result'][0]['indicators']['quote'][0]['close']
                    
                    # Create DataFrames
                    stock_df = pd.DataFrame({'close': stock_close})
                    index_df = pd.DataFrame({'close': index_close})
                    
                    # Calculate returns
                    stock_df['return'] = stock_df['close'].pct_change().fillna(0)
                    index_df['return'] = index_df['close'].pct_change().fillna(0)
                    
                    # Ensure same length
                    min_len = min(len(stock_df), len(index_df))
                    stock_returns = stock_df['return'].iloc[:min_len].values
                    index_returns = index_df['return'].iloc[:min_len].values
                    
                    # Calculate correlation
                    correlation = round(np.corrcoef(stock_returns, index_returns)[0, 1], 2)
            except:
                pass
            
            return {
                'symbol': symbol,
                'index_symbol': index_symbol,
                'period_days': days,
                'correlation': correlation,
                'correlated_drops': len(correlated_drops),
                'stock_specific_drops': len(market_specific_drops),
                'correlated_drop_details': correlated_drops,
                'stock_specific_drop_details': market_specific_drops
            }
            
        except Exception as e:
            return {'error': f"Error analyzing market conditions: {str(e)}"}
    
    def calculate_drop_statistics(self, symbol, years=5):
        """
        Calculate historical drop statistics for a stock
        
        Args:
            symbol (str): Stock symbol
            years (int): Number of years to analyze
            
        Returns:
            dict: Drop statistics
        """
        try:
            # Get long-term data
            stock_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                             query={'symbol': symbol, 
                                                   'interval': '1d', 
                                                   'range': f"{years}y"})
            
            if not stock_data or 'chart' not in stock_data or 'result' not in stock_data['chart']:
                return {'error': f"Failed to fetch data for {symbol}"}
            
            result = stock_data['chart']['result'][0]
            
            # Extract timestamp and price data
            timestamps = result['timestamp']
            indicators = result['indicators']
            
            # Get quote data
            quote = indicators['quote'][0]
            close_prices = quote.get('close', [])
            
            # Convert timestamps to dates
            dates = [datetime.fromtimestamp(ts).strftime('%Y-%m-%d') for ts in timestamps]
            
            # Create DataFrame for analysis
            df = pd.DataFrame({
                'date': dates,
                'timestamp': timestamps,
                'close': close_prices
            })
            
            # Remove rows with None values
            df = df.dropna(subset=['close'])
            
            # Calculate daily returns
            df['daily_return'] = df['close'].pct_change()
            
            # Calculate statistics
            stats = {
                'symbol': symbol,
                'period_years': years,
                'total_trading_days': len(df),
                'drop_thresholds': {}
            }
            
            # Calculate statistics for different drop thresholds
            for threshold in [-0.01, -0.02, -0.03, -0.05, -0.10]:
                drops = df[df['daily_return'] <= threshold]
                
                stats['drop_thresholds'][str(threshold)] = {
                    'threshold_pct': round(threshold * 100, 2),
                    'count': len(drops),
                    'percentage_of_days': round(len(drops) / len(df) * 100, 2) if len(df) > 0 else 0,
                    'avg_drop_size': round(drops['daily_return'].mean() * 100, 2) if len(drops) > 0 else 0,
                    'max_drop_size': round(drops['daily_return'].min() * 100, 2) if len(drops) > 0 else 0,
                    'avg_recovery_days': None  # Will calculate below
                }
            
            # Calculate average recovery time for 5% drops
            recovery_days = []
            five_pct_drops = df[df['daily_return'] <= -0.05].index.tolist()
            
            for drop_idx in five_pct_drops:
                if drop_idx >= len(df) - 1:
                    continue
                
                drop_price = df.iloc[drop_idx]['close']
                
                # Find recovery day
                recovery_idx = None
                for i in range(drop_idx + 1, len(df)):
                    if df.iloc[i]['close'] >= drop_price:
                        recovery_idx = i
                        break
                
                if recovery_idx is not None:
                    recovery_days.append(recovery_idx - drop_idx)
            
            if recovery_days:
                stats['drop_thresholds']['-0.05']['avg_recovery_days'] = round(sum(recovery_days) / len(recovery_days), 1)
            
            return stats
            
        except Exception as e:
            return {'error': f"Error calculating drop statistics: {str(e)}"}

# Test function
def test_drop_detector():
    """Test the DropDetector class functionality"""
    detector = DropDetector()
    
    # Test with Apple stock
    apple_drops = detector.detect_drops('AAPL', threshold=-0.03, days=90, consecutive_days=True)
    
    # Test market condition analysis
    market_analysis = detector.analyze_market_conditions('AAPL')
    
    # Test drop statistics
    drop_stats = detector.calculate_drop_statistics('AAPL', years=3)
    
    # Print results
    print("Drop detection tests completed.")
    
    return {
        'drops': apple_drops,
        'market_analysis': market_analysis,
        'statistics': drop_stats
    }

if __name__ == "__main__":
    test_drop_detector()
