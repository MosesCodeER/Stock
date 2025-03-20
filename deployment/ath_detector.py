#!/usr/bin/env python3
"""
All-Time High Detector Module - Enhanced algorithms for detecting and analyzing stock all-time highs
"""

import sys
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Add path for data API access
sys.path.append('/opt/.manus/.sandbox-runtime')
from data_api import ApiClient

class ATHDetector:
    def __init__(self):
        """Initialize the ATHDetector class with Yahoo Finance API client"""
        self.client = ApiClient()
    
    def detect_all_time_highs(self, symbol, range='max', interval='1d'):
        """
        Detect all-time highs for a stock with enhanced detection
        
        Args:
            symbol (str): Stock symbol
            range (str): Data range to analyze (1mo, 3mo, 6mo, 1y, 5y, max)
            interval (str): Data interval (1d, 1wk, 1mo)
            
        Returns:
            dict: All-time high detection results
        """
        try:
            # Call Yahoo Finance API to get stock chart data
            stock_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                             query={'symbol': symbol, 
                                                   'interval': interval, 
                                                   'range': range,
                                                   'includeAdjustedClose': True})
            
            # Process the response
            if not stock_data or 'chart' not in stock_data or 'result' not in stock_data['chart']:
                return {'error': f"Failed to fetch data for {symbol}"}
            
            result = stock_data['chart']['result'][0]
            
            # Extract metadata
            meta = result['meta']
            
            # Extract timestamp and price data
            timestamps = result['timestamp']
            indicators = result['indicators']
            
            # Get quote data (open, high, low, close, volume)
            quote = indicators['quote'][0]
            close_prices = quote.get('close', [])
            high_prices = quote.get('high', [])
            
            # Convert timestamps to dates
            dates = [datetime.fromtimestamp(ts).strftime('%Y-%m-%d') for ts in timestamps]
            
            # Create DataFrame for analysis
            df = pd.DataFrame({
                'date': dates,
                'timestamp': timestamps,
                'close': close_prices,
                'high': high_prices
            })
            
            # Remove rows with None values
            df = df.dropna(subset=['close'])
            
            # Find all-time highs (where price is higher than all previous prices)
            ath_events = []
            current_ath = None
            
            for idx, row in df.iterrows():
                if idx == 0:
                    current_ath = row['close']
                    ath_events.append({
                        'date': row['date'],
                        'price': row['close'],
                        'type': 'initial'
                    })
                elif row['close'] > current_ath:
                    current_ath = row['close']
                    ath_events.append({
                        'date': row['date'],
                        'price': row['close'],
                        'type': 'new_ath'
                    })
            
            # Get current price and calculate metrics
            current_price = meta.get('regularMarketPrice')
            all_time_high = max(close_prices) if close_prices else None
            all_time_high_date = None
            
            if all_time_high:
                all_time_high_idx = close_prices.index(all_time_high)
                all_time_high_date = dates[all_time_high_idx]
            
            # Calculate percentage from ATH
            pct_from_ath = None
            is_at_ath = False
            
            if all_time_high and current_price:
                pct_from_ath = round((current_price - all_time_high) / all_time_high * 100, 2)
                is_at_ath = pct_from_ath >= -0.5  # Within 0.5% of ATH
            
            # Calculate additional metrics
            days_since_ath = None
            if all_time_high_date:
                ath_datetime = datetime.strptime(all_time_high_date, '%Y-%m-%d')
                days_since_ath = (datetime.now() - ath_datetime).days
            
            # Calculate ATH frequency
            ath_frequency = None
            if len(df) > 0 and len(ath_events) > 1:
                ath_frequency = round(len(df) / len(ath_events), 1)  # Trading days per ATH
            
            # Identify consolidation periods near ATH
            consolidation_periods = []
            if len(df) > 20:  # Need at least 20 days of data
                # Calculate rolling max
                df['rolling_max'] = df['close'].rolling(window=20).max()
                
                # Identify periods where price stayed within 5% of ATH for at least 10 days
                in_consolidation = False
                consolidation_start = None
                consolidation_days = 0
                
                for idx, row in df.iterrows():
                    if idx < 20:  # Skip first 20 days due to rolling window
                        continue
                    
                    if row['close'] >= 0.95 * row['rolling_max']:
                        if not in_consolidation:
                            in_consolidation = True
                            consolidation_start = row['date']
                        consolidation_days += 1
                    else:
                        if in_consolidation and consolidation_days >= 10:
                            consolidation_periods.append({
                                'start_date': consolidation_start,
                                'end_date': df.iloc[idx-1]['date'],
                                'days': consolidation_days,
                                'avg_price': round(df.iloc[idx-consolidation_days:idx]['close'].mean(), 2)
                            })
                        in_consolidation = False
                        consolidation_days = 0
                
                # Check if we're currently in consolidation
                if in_consolidation and consolidation_days >= 10:
                    consolidation_periods.append({
                        'start_date': consolidation_start,
                        'end_date': df.iloc[-1]['date'],
                        'days': consolidation_days,
                        'avg_price': round(df.iloc[-consolidation_days:]['close'].mean(), 2)
                    })
            
            return {
                'symbol': symbol,
                'range': range,
                'all_time_high': all_time_high,
                'all_time_high_date': all_time_high_date,
                'current_price': current_price,
                'percent_from_ath': pct_from_ath,
                'is_at_ath': is_at_ath,
                'days_since_ath': days_since_ath,
                'ath_occurrences': len(ath_events),
                'ath_frequency': ath_frequency,  # Trading days per ATH
                'ath_history': ath_events,
                'consolidation_periods': consolidation_periods
            }
            
        except Exception as e:
            return {'error': f"Error detecting all-time highs for {symbol}: {str(e)}"}
    
    def analyze_ath_breakouts(self, symbol, lookback_years=5):
        """
        Analyze breakouts from previous all-time highs
        
        Args:
            symbol (str): Stock symbol
            lookback_years (int): Number of years to look back
            
        Returns:
            dict: Breakout analysis results
        """
        try:
            # Get long-term data
            stock_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                             query={'symbol': symbol, 
                                                   'interval': '1d', 
                                                   'range': f"{lookback_years}y",
                                                   'includeAdjustedClose': True})
            
            if not stock_data or 'chart' not in stock_data or 'result' not in stock_data['chart']:
                return {'error': f"Failed to fetch data for {symbol}"}
            
            result = stock_data['chart']['result'][0]
            
            # Extract timestamp and price data
            timestamps = result['timestamp']
            indicators = result['indicators']
            
            # Get quote data
            quote = indicators['quote'][0]
            close_prices = quote.get('close', [])
            volume = quote.get('volume', [])
            
            # Convert timestamps to dates
            dates = [datetime.fromtimestamp(ts).strftime('%Y-%m-%d') for ts in timestamps]
            
            # Create DataFrame for analysis
            df = pd.DataFrame({
                'date': dates,
                'timestamp': timestamps,
                'close': close_prices,
                'volume': volume
            })
            
            # Remove rows with None values
            df = df.dropna(subset=['close'])
            
            # Calculate rolling 52-week high
            df['52w_high'] = df['close'].rolling(window=252).max()
            
            # Identify breakout events (when price exceeds previous 52-week high)
            breakout_events = []
            
            for idx, row in df.iterrows():
                if idx < 252:  # Skip first year due to rolling window
                    continue
                
                # Check if today's close is higher than previous 52-week high
                if row['close'] > df.iloc[idx-1]['52w_high']:
                    # Calculate volume increase
                    avg_volume = df.iloc[idx-20:idx]['volume'].mean()
                    volume_increase = round((row['volume'] / avg_volume - 1) * 100, 2) if avg_volume > 0 else None
                    
                    breakout_events.append({
                        'date': row['date'],
                        'breakout_price': row['close'],
                        'previous_high': df.iloc[idx-1]['52w_high'],
                        'breakout_percentage': round((row['close'] / df.iloc[idx-1]['52w_high'] - 1) * 100, 2),
                        'volume': row['volume'],
                        'volume_increase': volume_increase
                    })
            
            # Analyze performance after breakouts
            for i, breakout in enumerate(breakout_events):
                breakout_idx = df[df['date'] == breakout['date']].index[0]
                
                # Calculate performance after breakout (1 week, 1 month, 3 months)
                for days, label in [(5, '1w'), (21, '1m'), (63, '3m')]:
                    if breakout_idx + days < len(df):
                        future_price = df.iloc[breakout_idx + days]['close']
                        performance = round((future_price / breakout['breakout_price'] - 1) * 100, 2)
                        breakout[f'performance_{label}'] = performance
            
            # Calculate success rate of breakouts
            success_rates = {}
            for period in ['1w', '1m', '3m']:
                successful = sum(1 for b in breakout_events if b.get(f'performance_{period}', 0) > 0)
                total = sum(1 for b in breakout_events if f'performance_{period}' in b)
                success_rates[period] = round(successful / total * 100, 2) if total > 0 else None
            
            return {
                'symbol': symbol,
                'lookback_years': lookback_years,
                'total_breakouts': len(breakout_events),
                'breakout_events': breakout_events,
                'success_rates': success_rates,
                'avg_breakout_percentage': round(np.mean([b['breakout_percentage'] for b in breakout_events]), 2) if breakout_events else None,
                'avg_volume_increase': round(np.mean([b['volume_increase'] for b in breakout_events if b['volume_increase'] is not None]), 2) if breakout_events else None
            }
            
        except Exception as e:
            return {'error': f"Error analyzing ATH breakouts for {symbol}: {str(e)}"}
    
    def compare_sector_performance(self, symbol, sector_etf=None):
        """
        Compare stock's ATH performance with its sector
        
        Args:
            symbol (str): Stock symbol
            sector_etf (str): Sector ETF symbol (if None, will be determined based on stock)
            
        Returns:
            dict: Sector comparison results
        """
        try:
            # If sector ETF not provided, determine based on stock
            if not sector_etf:
                # Get stock insights to determine sector
                insights = self.client.call_api('YahooFinance/get_stock_insights', 
                                              query={'symbol': symbol})
                
                # Map sectors to ETFs
                sector_etfs = {
                    'Technology': 'XLK',
                    'Financial': 'XLF',
                    'Health Care': 'XLV',
                    'Consumer Discretionary': 'XLY',
                    'Consumer Staples': 'XLP',
                    'Energy': 'XLE',
                    'Industrials': 'XLI',
                    'Materials': 'XLB',
                    'Utilities': 'XLU',
                    'Real Estate': 'XLRE',
                    'Communication Services': 'XLC'
                }
                
                # Default to SPY (S&P 500) if sector can't be determined
                sector_etf = 'SPY'
                
                if (insights and 'finance' in insights and 'result' in insights['finance'] and 
                    'instrumentInfo' in insights['finance']['result'] and 
                    'technicalEvents' in insights['finance']['result']['instrumentInfo']):
                    
                    sector = insights['finance']['result']['instrumentInfo']['technicalEvents'].get('sector')
                    if sector in sector_etfs:
                        sector_etf = sector_etfs[sector]
            
            # Get stock ATH data
            stock_ath = self.detect_all_time_highs(symbol, range='5y')
            
            # Get sector ETF ATH data
            sector_ath = self.detect_all_time_highs(sector_etf, range='5y')
            
            # Calculate relative performance
            relative_performance = None
            if ('percent_from_ath' in stock_ath and stock_ath['percent_from_ath'] is not None and
                'percent_from_ath' in sector_ath and sector_ath['percent_from_ath'] is not None):
                relative_performance = round(stock_ath['percent_from_ath'] - sector_ath['percent_from_ath'], 2)
            
            # Determine if stock is outperforming sector
            outperforming = None
            if relative_performance is not None:
                outperforming = relative_performance > 0
            
            return {
                'symbol': symbol,
                'sector_etf': sector_etf,
                'stock_ath': stock_ath['all_time_high'],
                'stock_ath_date': stock_ath['all_time_high_date'],
                'stock_pct_from_ath': stock_ath['percent_from_ath'],
                'sector_ath': sector_ath['all_time_high'],
                'sector_ath_date': sector_ath['all_time_high_date'],
                'sector_pct_from_ath': sector_ath['percent_from_ath'],
                'relative_performance': relative_performance,
                'outperforming_sector': outperforming
            }
            
        except Exception as e:
            return {'error': f"Error comparing sector performance for {symbol}: {str(e)}"}

# Test function
def test_ath_detector():
    """Test the ATHDetector class functionality"""
    detector = ATHDetector()
    
    # Test with Apple stock
    apple_ath = detector.detect_all_time_highs('AAPL', range='5y')
    
    # Test breakout analysis
    breakout_analysis = detector.analyze_ath_breakouts('AAPL', lookback_years=3)
    
    # Test sector comparison
    sector_comparison = detector.compare_sector_performance('AAPL')
    
    # Print results
    print("All-time high detection tests completed.")
    
    return {
        'ath': apple_ath,
        'breakout_analysis': breakout_analysis,
        'sector_comparison': sector_comparison
    }

if __name__ == "__main__":
    test_ath_detector()
