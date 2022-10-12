import argparse

class Menu(object):

    def __init__(self):
        self.parser = argparse.ArgumentParser(description = 'l2Defender')
        self.parser.add_argument('-i',
                                 help = 'Interface to be monitored',
                                 metavar = '<interface>',
                                 required = True)
