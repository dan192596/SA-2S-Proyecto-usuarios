from django.contrib.auth.models import User
from rest_framework import serializers

#Serializador para retornar la lista de todas las clases existentes
class UserSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField('get_username')    
    nombres = serializers.SerializerMethodField('get_first_name')
    apellidos = serializers.SerializerMethodField('get_last_name')
    administrador = serializers.SerializerMethodField('get_is_superuser')

    class Meta:
        model = User
        fields = ('id', 'nombres', 'apellidos', 'administrador')

    def get_username(self, obj):
        return obj.username

    def get_first_name(self, obj):
        return obj.first_name
    
    def get_last_name(self, obj):
        return obj.last_name

    def get_is_superuser(self, obj):
        return obj.is_superuser
    